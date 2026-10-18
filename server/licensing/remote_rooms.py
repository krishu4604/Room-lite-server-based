"""Bounded, server-owned manual room sockets. Never return gateway credentials."""
import asyncio
import contextlib
import threading
import time
import uuid

from licensing.service import Denied


class RemoteRooms:
    def __init__(self, store, factory, limit=4, accounts=None):
        self.store, self.factory, self.limit = store, factory, limit
        self.accounts=accounts
        self.rows = {}
        self.lock = threading.RLock()
        self.loop = None
        self.thread = None

    def _loop(self):
        with self.lock:
            if self.loop is None:
                self.loop = asyncio.new_event_loop()
                self.thread = threading.Thread(target=self.loop.run_forever, name='remote-room-loop', daemon=True)
                self.thread.start()
            return self.loop

    def active(self):
        with self.lock:
            return [r for r in self.rows.values() if r['state'] in ('connecting', 'joined', 'stopping') or r['state'] == 'cleanup_unknown' and r['until'] > time.time()]

    def start(self, device, group, index, account, room, password, seconds):
        from backend.room_credentials import gateway_credentials
        uid = gateway_credentials(account)[0]
        with self.lock:
            active = self.active()
            if len(active) >= self.limit or sum(r['device'] == device for r in active) >= 4:
                raise Denied('Room capacity reached.')
            if any(r['uid'] == uid for r in active):
                raise Denied('This account already has a remote room session.')
            session = uuid.uuid4().hex
            row = dict(id=session, device=device, group=group, index=index, uid=uid, room=str(room),
                       state='connecting', until=time.time() + seconds, seat=None, sent=0,
                       stop=threading.Event(), calls=set(), service=None, ktv=None, error='')
            # Bound completed history too; credentials never enter history.
            for old in list(self.rows):
                if len(self.rows) < 64:
                    break
                if self.rows[old] not in active:
                    del self.rows[old]
            self.rows[session] = row
            row['future'] = asyncio.run_coroutine_threadsafe(self._run(row, account, int(room), password), self._loop())
            def finished(future):
                if row['service'] is None and row['state'] == 'connecting':
                    row['state'] = 'stopped' if row['stop'].is_set() else 'failed'
                    if not row['stop'].is_set():
                        row['error'] = 'Session could not start.'
            row['future'].add_done_callback(finished)
            return {'session': session, 'state': 'connecting', 'expires_at': int(row['until'])}

    def _authorize(self, row):
        if row['stop'].is_set() or time.time() >= row['until']:
            raise Denied('Room session stopped or duration expired.')
        if row['group'] is None:
            self.store.permission(row['device'],'room',False)
            account=self.accounts.get(row['device'],row['index'])
            if account['uid'] != row['uid']:
                raise Denied('Account slot changed. Reconnect explicitly.')
        else:
            self.store.job_permission(row['device'], row['group'], feature='room', active=False)

    async def _run(self, row, account, room, password):
        service = self.factory()
        row['service'] = service
        owner = asyncio.current_task()

        async def guard():
            while True:
                try:
                    await asyncio.to_thread(self._authorize, row)
                except Exception:
                    row['error'] = 'Session stopped: permission, duration or server storage unavailable.'
                    row['stop'].set()
                    owner.cancel()
                    return
                await asyncio.sleep(1)

        watcher = asyncio.create_task(guard())
        try:
            await asyncio.to_thread(self._authorize, row)
            await asyncio.wait_for(service.join(room, account, password), 25)
            account = password = None
            if not row['stop'].is_set():
                row['state'] = 'joined'
            from backend.ktv_control import KtvControl
            row['ktv'] = KtvControl(service, row['uid'])
            next_ktv=0
            while not row['stop'].is_set():
                if getattr(service, 'state', 'joined') == 'failed':
                    raise RuntimeError('Gateway closed')
                row['seat'] = getattr(service, 'seat_id', None)
                if row['ktv'].watching and time.monotonic()>=next_ktv:
                    next_ktv=time.monotonic()+2
                    try:
                        await asyncio.to_thread(self.store.permission,row['device'],'ktv',False)
                        async with row['ktv'].lock:
                            await row['ktv'].refresh()
                    except Exception:
                        row['ktv'].pending_song=None
                        row['ktv'].watching=False
                        row['ktv'].singer={}
                        row['ktv'].error='Queue verification failed. Refresh before continuing.'
                        raise RuntimeError('KTV verification lost; disconnecting the authenticated session')
                await asyncio.sleep(.2)
        except asyncio.CancelledError:
            pass
        except Exception:
            row['error'] = 'Gateway operation failed. No automatic retry.'
        finally:
            row['state'] = 'stopping'
            watcher.cancel()
            for future in list(row['calls']):
                future.cancel()
            with contextlib.suppress(BaseException):
                await watcher
            try:
                await asyncio.wait_for(service.leave(), 4)
                row['state'] = 'failed' if row['error'] else 'stopped'
            except BaseException:
                row['state'] = 'cleanup_unknown'
                row['error'] = 'Disconnect could not be confirmed.'
            row['service'] = None
            account = password = None

    def _owned(self, device, session):
        with self.lock:
            row = self.rows.get(session)
            if row is None or row['device'] != device:
                raise Denied('Room session unavailable.')
            return row

    def stop(self, device, session=None):
        with self.lock:
            rows = [self._owned(device, session)] if session else [r for r in self.rows.values() if r['device'] == device]
            for row in rows:
                row['stop'].set()
                for future in list(row['calls']):
                    future.cancel()
                # Cancellation of the owner invokes its bounded cleanup.
                if row['state'] in ('connecting', 'joined'):
                    row['future'].cancel()

    def action(self, device, session, operation, args):
        row = self._owned(device, session)

        async def execute():
            await asyncio.to_thread(self._authorize, row)
            if row['stop'].is_set() or row['state'] != 'joined' or row['service'] is None:
                raise Denied('Room is not joined.')
            service = row['service']
            if operation == 'chat.send':
                await service.send_chat(args['text'])
                row['sent'] += 1
            elif operation == 'seat.take':
                await service.take_seat(args['seat'])
            elif operation == 'seat.apply':
                await service.apply_for_seat()
            elif operation == 'seat.cancel':
                await service.cancel_seat_application()
            elif operation.startswith('ktv.'):
                await asyncio.to_thread(self.store.permission,device,'ktv',False)
                return {'ktv':await row['ktv'].action(operation,args.get('song'))}
            row['seat'] = getattr(service, 'seat_id', None)

        future = asyncio.run_coroutine_threadsafe(execute(), self._loop())
        row['calls'].add(future)
        try:
            response=future.result(timeout=15)
            return {'session': session, 'upstream_acknowledged': True, 'public_delivery_verified': False, **(response or {})}
        except TimeoutError:
            # Do not resend on uncertain acknowledgement.
            return {'session': session, 'outcome_unknown': True, 'retry_allowed': False}
        finally:
            if future.done():
                row['calls'].discard(future)
            else:
                future.add_done_callback(lambda done: row['calls'].discard(done))

    def audio(self, device, session, mode, source=None, ktv=False):
        row=self._owned(device,session)
        async def authorize():
            await asyncio.to_thread(self._authorize,row)
            if row['state']!='joined' or row['service'] is None:
                raise Denied('Join this account on the server first.')
            if source:
                origin=self._owned(device,source)
                await asyncio.to_thread(self._authorize,origin)
                if origin['state']!='joined' or origin['uid']==row['uid'] or origin['room']==row['room']:
                    raise Denied('Route needs two distinct authenticated memberships.')
            publish=False
            if mode=='publish':
                if ktv:
                    await asyncio.to_thread(self.store.permission,device,'ktv',False)
                    async with row['ktv'].lock:
                        await row['ktv'].refresh()
                        publish=row['ktv'].can_publish()
                else:
                    from backend import room_protocol as p
                    service=row['service']
                    values=await service._request(p.GET_SEATS,p.room_request(service._token))
                    matching=[]
                    for raw in values.get(2,[]):
                        item=p.fields(raw)
                        if p.first(item,2,0)==row['uid']:
                            matching.append(item)
                    publish=len(matching)==1 and p.first(matching[0],1,0)>0 and p.first(matching[0],3,0)==0
                if not publish:
                    raise Denied('Upstream has not confirmed publishing permission for this account.')
            await asyncio.to_thread(self._authorize,row)
            if row['state']!='joined' or row['service'] is None:
                raise Denied('Audio session ended during verification.')
            if source:
                await asyncio.to_thread(self._authorize,origin)
                if origin['state']!='joined':
                    raise Denied('Route source disconnected during verification.')
            return {'session':session,'room':row['room'],'uid':str(row['uid']),
                    'publish':publish,'valid_for_ms':5000}
        future=asyncio.run_coroutine_threadsafe(authorize(),self._loop())
        try:
            return future.result(timeout=6)
        except TimeoutError:
            future.cancel()
            raise Denied('Audio authorization timed out. Microphone must remain off.') from None

    def status(self, device):
        with self.lock:
            return [{k: r[k] for k in ('id', 'group', 'index', 'room', 'state', 'seat', 'sent', 'error')} |
                    {'expires_at': int(r['until']), 'ktv':r['ktv'].public() if r['ktv'] else None} for r in self.rows.values() if r['device'] == device]

    def close(self):
        with self.lock:
            devices = {r['device'] for r in self.rows.values()}
        for device in devices:
            self.stop(device)
        if self.loop:
            async def drain():
                pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                # Cancelling to_thread does not stop its database worker. Drain
                # those workers before closing the loop/store (notably SQLite
                # on Windows, which otherwise leaves an in-use database file).
                await self.loop.shutdown_default_executor(timeout=4)
            # Shutdown/test only; allow bounded disconnect finalizers to finish.
            with contextlib.suppress(Exception):
                asyncio.run_coroutine_threadsafe(drain(), self.loop).result(timeout=6)
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=2)
            if not self.thread.is_alive():
                self.loop.close()
