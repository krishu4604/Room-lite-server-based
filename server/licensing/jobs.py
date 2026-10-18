"""Bounded server-owned chat workers. Device never receives gateway credentials."""
import asyncio
import threading
import time
from licensing.service import Denied

# Brief, job-local authorization snapshot; never an offline subscription lease.
AUTH_REFRESH_SECONDS = 1.0
AUTH_MAX_AGE_SECONDS = 2.5


class Jobs:
    def __init__(self, store, factory=None):
        self.store = store
        if factory is None:
            from backend.room_service import RoomService
            factory = RoomService
        self.factory = factory
        self.lock = threading.RLock()
        self.jobs = {}

    def start(self, device, data):
        panel = data["panel"]
        if type(panel) is not int or panel not in range(4):
            raise Denied("Invalid panel.")
        room = data["room"]
        messages = data["messages"]
        delay = data["delay_ms"]
        rounds = data["rounds"]
        password = data.get("password", "")
        if type(room) is not int or not 0 < room < 2**63 or not isinstance(password, str) or len(password) > 256:
            raise Denied("Invalid room.")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 100 or any(not isinstance(m, str) or not m.strip() or len(m) > 1000 for m in messages):
            raise Denied("Invalid messages.")
        if type(delay) is not int or not 0 <= delay <= 3600000 or type(rounds) is not int or not 0 <= rounds <= 10000:
            raise Denied("Invalid delay or rounds.")
        accounts = self.store.accounts(device, data["group"])
        from backend.room_credentials import gateway_credentials
        uids = {gateway_credentials(a)[0] for a in accounts}
        config = (room, password, tuple(messages), delay, rounds)
        with self.lock:
            # Finite global capacity, shared settings per device and exclusive account ownership.
            active = [j for j in self.jobs.values() if j["running"]]
            if len(active) >= 16:
                raise Denied("Server capacity reached.")
            for job in active:
                if job["uids"] & uids:
                    raise Denied("An account group is already in use.")
                if job["device"] == device and (job["panel"] == panel or job["config"] != config):
                    raise Denied("Panel active or shared settings differ. Stop first.")
            job = dict(device=device, panel=panel, config=config, group=data["group"], uids=uids,
                       running=True, phase="Starting", sent=0, failed=0, round=0, connected=0,
                       stop=threading.Event(), created=time.time())
            self.jobs[device, panel] = job
            threading.Thread(target=self._thread, args=(job, accounts), daemon=True).start()
        return {"ok": True, "panel": panel}

    def _thread(self, job, accounts):
        asyncio.run(self._run(job, accounts))

    def _allowed(self, job):
        if job["stop"].is_set() or time.time() - job["created"] > 86400:
            raise Denied("Job stopped.")
        if time.monotonic() >= job.get("authorization_until", 0):
            raise Denied("Job authorization expired.")

    async def _refresh_authorization(self, job):
        started = time.monotonic()
        # Synchronous Atlas calls must not block gateway readers or heartbeats.
        row = await asyncio.to_thread(self.store.job_permission, job["device"], job["group"])
        remaining = min(row["expires"], row["active_until"]) - time.time()
        job["authorization_until"] = min(started + AUTH_MAX_AGE_SECONDS, time.monotonic() + remaining)
        self._allowed(job)

    async def _run(self, job, accounts):
        room, password, messages, delay, rounds = job["config"]
        live = {}
        loop = asyncio.get_running_loop()
        job["loop"] = loop
        job["task"] = asyncio.current_task()
        async def watchdog():
            while True:
                await asyncio.sleep(AUTH_REFRESH_SECONDS)
                try:
                    await self._refresh_authorization(job)
                except Exception:
                    # Loss of Atlas access is not permission to continue a job.
                    self._signal_stop(job)
                    return
        async def expiry_guard():
            while True:
                await asyncio.sleep(.1)
                try:
                    self._allowed(job)
                except Denied:
                    self._signal_stop(job)
                    return
        monitors = []
        try:
            await self._refresh_authorization(job)
            monitors = [asyncio.create_task(watchdog()), asyncio.create_task(expiry_guard())]
            ordinal = 0
            for round_number in range(1, (rounds or 10000) + 1):
                job["round"] = round_number
                for index, account in enumerate(accounts):
                    self._allowed(job)
                    gateway = live.get(index)
                    if round_number == 1:
                        gateway = self.factory()
                        live[index] = gateway
                        try:
                            await gateway.join(room, account, password)
                        except Exception:
                            job["failed"] += 1
                            await gateway.leave()
                            live.pop(index, None)
                            continue
                    if gateway is None:
                        continue
                    job["connected"] = len(live)
                    job["phase"] = "Running"
                    self._allowed(job)
                    try:
                        await gateway.send_chat(messages[ordinal % len(messages)])
                        ordinal += 1
                        job["sent"] += 1
                    except Exception:
                        job["failed"] += 1
                        await gateway.leave()
                        live.pop(index, None)
                    # Zero means no configured delay; gateway acknowledgements still apply.
                    await asyncio.sleep(delay / 1000 if delay else 0)
                if not live:
                    job["phase"] = "No healthy accounts"
                    return
            job["phase"] = "Completed"
        except (Denied, asyncio.CancelledError):
            job["phase"] = "Stopped"
        except Exception:
            job["phase"] = "Failed"
        finally:
            with self.lock:
                job["cleaning"] = True
            try:
                for monitor in monitors:
                    monitor.cancel()
                await asyncio.gather(*monitors, return_exceptions=True)
                close = lambda g: g.abort() if job["stop"].is_set() and hasattr(g, "abort") else g.leave()
                await asyncio.gather(*(close(g) for g in live.values()), return_exceptions=True)
            finally:
                with self.lock:
                    job["connected"] = 0
                    job["running"] = False
                    if job["stop"].is_set():
                        job["phase"] = "Stopped"
                    job.pop("loop", None)
                    job.pop("task", None)

    def _signal_stop(self, job):
        with self.lock:
            if not job["running"] or job["stop"].is_set():
                return
            job["stop"].set()
            job["phase"] = "Stopping"
            loop, task = job.get("loop"), job.get("task")
            if loop and task and not loop.is_closed() and not job.get("cleaning"):
                # Repeated Stop must not cancel the cleanup coroutine.
                loop.call_soon_threadsafe(task.cancel)

    def stop(self, device, panel=None):
        if panel is not None and (type(panel) is not int or panel not in range(4)):
            raise Denied("Invalid panel.")
        with self.lock:
            for job in self.jobs.values():
                if job["device"] == device and (panel is None or panel == job["panel"]):
                    self._signal_stop(job)

    def status(self, device):
        with self.lock:
            return [{key: j[key] for key in ("panel", "group", "running", "phase", "sent", "failed", "round", "connected")}
                    for j in self.jobs.values() if j["device"] == device]
