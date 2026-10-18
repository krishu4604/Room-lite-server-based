"""Independent Room Lite licensing API. No credentials are returned to clients."""
import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, request

FEATURES = {"room", "audio", "music", "effects", "multi_account", "auto_chat", "audio_target", "ktv"}
LEASE_SECONDS = 180
REMOTE_ACTIONS = frozenset({"/v2/remote/state", "/v2/remote/command", "/v2/remote/audio"})


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class Denied(Exception):
    pass


class Store:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.signer = serialization.load_pem_private_key((self.root / "signing.pem").read_bytes(), None)
        self.cipher = AESGCM((self.root / "accounts.key").read_bytes())
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY, public_key TEXT NOT NULL, features TEXT NOT NULL DEFAULT '[]',
                    expires INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
                    active_until INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS challenges (
                    nonce TEXT PRIMARY KEY, device TEXT NOT NULL, action TEXT NOT NULL,
                    digest TEXT NOT NULL, expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS limits (
                    bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS groups (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, encrypted BLOB NOT NULL, count INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS grants (
                    device TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY(device,group_id));
            """)

    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.root / "licenses.sqlite", timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def throttle(self, ip):
        now = int(time.time())
        bucket = hashlib.sha256(ip.encode()).hexdigest() + ":" + str(now // 60)
        count = self.increment_limit(bucket, now + 120)
        if count > 120:
            raise Denied("Request limit reached. Retry later.")

    def challenge(self, public_key, action, digest):
        if action not in {"/v1/lease", "/v1/groups", "/v1/jobs/start", "/v1/jobs/status", "/v1/jobs/stop", "/v1/resolve"} | REMOTE_ACTIONS:
            raise Denied("Unsupported action.")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise Denied("Invalid request digest.")
        der = unb64(public_key)
        key = serialization.load_der_public_key(der)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise Denied("Unsupported device key.")
        device = hashlib.sha256(der).hexdigest()
        nonce = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM challenges WHERE expires<?", (now,))
            db.execute("INSERT OR IGNORE INTO devices(id,public_key) VALUES (?,?)", (device, public_key))
            # UI and foreground media may legitimately request the same action
            # concurrently. Keep a small bounded set, not one destructive slot.
            if db.execute("SELECT COUNT(*) FROM challenges WHERE device=? AND action=?", (device,action)).fetchone()[0]>=8:
                raise Denied("Too many pending device proofs. Wait for expiry.")
            db.execute("INSERT INTO challenges VALUES (?,?,?,?,?)", (nonce, device, action, digest, now + 60))
        return {"device": device, "nonce": nonce, "expires": now + 60}

    def authenticate(self, body, action):
        device, nonce = body["device"], body["nonce"]
        raw = unb64(body["payload"])
        if len(raw) > 20000:
            raise Denied("Request too large.")
        digest = hashlib.sha256(raw).hexdigest()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM challenges WHERE nonce=?", (nonce,)).fetchone()
            account = db.execute("SELECT * FROM devices WHERE id=?", (device,)).fetchone()
            if not row or not account or row["device"] != device or row["action"] != action or row["digest"] != digest or row["expires"] <= time.time():
                raise Denied("Challenge expired or invalid.")
            key = serialization.load_der_public_key(unb64(account["public_key"]))
            key.verify(unb64(body["signature"]), (device + "\n" + nonce + "\n" + action + "\n" + digest).encode(), ec.ECDSA(hashes.SHA256()))
            db.execute("DELETE FROM challenges WHERE nonce=?", (nonce,))
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise Denied("Invalid payload.")
        return device, nonce, payload

    def permission(self, device, feature=None, active=False):
        with self.db() as db:
            row = db.execute("SELECT * FROM devices WHERE id=?", (device,)).fetchone()
        return self.check_permission(row, feature, active)

    @staticmethod
    def check_permission(row, feature=None, active=False):
        if not row or row["revoked"] or row["expires"] <= time.time():
            raise Denied("Subscription pending, expired or revoked.")
        if feature and feature not in json.loads(row["features"]):
            raise Denied("This feature is not in your plan.")
        if active and row["active_until"] <= time.time():
            raise Denied("Device session expired.")
        return row

    def job_permission(self, device, group, feature="auto_chat", active=True):
        row = self.permission(device, feature, active)
        with self.db() as db:
            assigned = db.execute("SELECT 1 FROM grants a JOIN groups g ON g.id=a.group_id WHERE a.device=? AND a.group_id=?", (device, group)).fetchone()
        if not assigned:
            raise Denied("Account group access revoked.")
        return row

    def lease(self, device, nonce):
        row = self.permission(device)
        now = int(time.time())
        expires = min(now + LEASE_SECONDS, row["expires"])
        raw = encode({"device": device, "nonce": nonce, "iat": now, "exp": expires,
                      "features": json.loads(row["features"]), "version": row["version"]})
        with self.db() as db:
            db.execute("UPDATE devices SET active_until=? WHERE id=?", (expires, device))
        return {"payload": b64(raw), "signature": b64(self.signer.sign(raw, padding.PKCS1v15(), hashes.SHA256()))}

    def groups(self, device, feature="auto_chat"):
        self.permission(device, feature, True)
        with self.db() as db:
            rows = db.execute("SELECT g.id,g.name,g.count FROM groups g JOIN grants a ON a.group_id=g.id WHERE a.device=? ORDER BY g.id", (device,)).fetchall()
        return [dict(row) for row in rows]

    def accounts(self, device, group, feature="auto_chat"):
        self.permission(device, feature, True)
        with self.db() as db:
            row = db.execute("SELECT g.* FROM groups g JOIN grants a ON a.group_id=g.id WHERE a.device=? AND g.id=?", (device, group)).fetchone()
        if not row:
            raise Denied("Account group is not assigned to this device.")
        blob = row["encrypted"]
        return json.loads(self.cipher.decrypt(blob[:12], blob[12:], group.encode()))

    def import_group(self, group, name, accounts):
        import re
        if not isinstance(group, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,48}", group):
            raise Denied("Use a group ID containing 1–48 letters, digits, underscores or hyphens.")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise Denied("Enter a group name of 1–80 characters.")
        if not isinstance(accounts, list) or not 1 <= len(accounts) <= 64:
            raise Denied("Group must contain 1–64 accounts.")
        from backend.room_credentials import gateway_credentials
        clean, seen = [], set()
        for account in accounts:
            if not isinstance(account, dict):
                raise Denied("Invalid account file.")
            candidate = dict(account)
            if candidate.get("user_session") and not candidate.get("oauth_token") and not candidate.get("access_token"):
                candidate["oauth_token"] = candidate["user_session"]
            try:
                uid, session, token, device = gateway_credentials(candidate)
            except Exception:
                raise Denied("An account is missing a valid UID, login token or device ID.") from None
            if uid in seen:
                raise Denied("File contains duplicate accounts.")
            if any(len(value) > 10000 for value in (session, token, device)):
                raise Denied("Account fields are too large.")
            seen.add(uid)
            clean.append({"uid": uid, "user_name": str(candidate.get("user_name") or candidate.get("name") or "Account")[:120],
                          "oauth_token": session, "oauth_version": "v1", "gateway_user_token": token, "device_id": device})
        nonce = secrets.token_bytes(12)
        encrypted = nonce + self.cipher.encrypt(nonce, encode(clean), group.encode())
        self.save_group(group, name.strip(), encrypted, len(clean))
        return {"id": group, "name": name.strip(), "count": len(clean)}

    def save_group(self, group, name, encrypted, count):
        with self.db() as db:
            db.execute("INSERT INTO groups VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,encrypted=excluded.encrypted,count=excluded.count", (group, name, encrypted, count))

    def increment_limit(self, bucket, expires):
        with self.db() as db:
            db.execute("DELETE FROM limits WHERE expires<?", (int(time.time()),))
            db.execute("INSERT INTO limits VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1", (bucket, expires))
            return db.execute("SELECT count FROM limits WHERE bucket=?", (bucket,)).fetchone()[0]

    def init_audit(self):
        with self.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, time INTEGER NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL)")

    def record_audit(self, action, target):
        with self.db() as db:
            db.execute("INSERT INTO audit(time,action,target) VALUES (?,?,?)", (int(time.time()), action, target))
            db.execute("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 2000)")

    def overview_rows(self):
        with self.db() as db:
            devices = [dict(row) for row in db.execute("SELECT id,features,expires,revoked,active_until,version FROM devices ORDER BY rowid DESC LIMIT 1000")]
            groups = [dict(row) for row in db.execute("SELECT id,name,count FROM groups ORDER BY name")]
            grants = [dict(row) for row in db.execute("SELECT device,group_id FROM grants")]
            events = [dict(row) for row in db.execute("SELECT time,action,target FROM audit ORDER BY id DESC LIMIT 100")]
        return devices, groups, grants, events

    def set_subscription(self, device, features, days, extend):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT expires FROM devices WHERE id=?", (device,)).fetchone()
            if not row:
                raise Denied("Unknown device. Activate it from the phone first.")
            base = max(int(time.time()), row["expires"]) if extend else int(time.time())
            db.execute("UPDATE devices SET features=?,expires=?,revoked=0,active_until=0,version=version+1 WHERE id=?", (json.dumps(sorted(features)), base + days * 86400, device))

    def revoke_device(self, device):
        with self.db() as db:
            if db.execute("UPDATE devices SET revoked=1,active_until=0,version=version+1 WHERE id=?", (device,)).rowcount != 1:
                raise Denied("Unknown device.")

    def assign_groups(self, device, selected):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM devices WHERE id=?", (device,)).fetchone():
                raise Denied("Unknown device.")
            known = {row[0] for row in db.execute("SELECT id FROM groups")}
            if not set(selected) <= known:
                raise Denied("Unknown account group.")
            db.execute("DELETE FROM grants WHERE device=?", (device,))
            db.executemany("INSERT INTO grants VALUES (?,?)", ((device, group) for group in set(selected)))

    def health(self):
        return True


def create_app(root=None, gateway_factory=None, store=None, public_ids=None):
    if store is None:
        if root is None and os.environ.get("MONGODB_URI"):
            from licensing.mongo_store import MongoStore
            store = MongoStore.from_environment()
        else:
            store = Store(root or os.environ["ROOMLITE_LICENSE_DATA"])
    from licensing.jobs import Jobs
    jobs = Jobs(store, gateway_factory)
    if public_ids is None:
        from licensing.public_ids import PublicIds
        public_ids = PublicIds()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 40000
    app.extensions["license_store"] = store
    app.extensions["license_jobs"] = jobs
    from licensing.admin import register_admin
    register_admin(app, store, jobs)

    @app.errorhandler(Exception)
    def failure(error):
        # Never expose gateway responses, account data, SQL or exception strings.
        return jsonify(error=str(error) if isinstance(error, Denied) else "Request rejected."), 403 if isinstance(error, Denied) else 400

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.get("/health")
    def health():
        try:
            if store.health():
                return {"ok": True, "resolver_protocol": 2, "lookup_diagnostics": 1}
        except Exception:
            pass
        return jsonify(ok=False), 503

    @app.post("/v1/challenge")
    def challenge():
        store.throttle(request.remote_addr or "unknown")
        body = request.get_json()
        return store.challenge(body["public_key"], body["action"], body["digest"])

    def auth(feature=None, active=True):
        device, nonce, payload = store.authenticate(request.get_json(), request.path)
        store.permission(device, feature, active)
        return device, nonce, payload

    @app.post("/v1/lease")
    def lease():
        device, nonce, _ = auth(active=False)
        return store.lease(device, nonce)

    @app.post("/v1/groups")
    def groups():
        device, _, _ = auth("auto_chat")
        return {"groups": store.groups(device)}

    @app.post("/v1/resolve")
    def resolve():
        device, _, payload = auth()
        now = int(time.time())
        if store.increment_limit("resolve:" + device + ":" + str(now // 60), now + 120) > 30:
            raise Denied("Lookup limit reached. Retry in a minute.")
        try:
            if "lookup_account" in payload:
                if not isinstance(payload["lookup_account"], dict):
                    raise Denied("Invalid selected-account lookup credentials. Sign in again.")
                return public_ids.resolve(payload.get("kind"), payload.get("value"), lookup_account=payload["lookup_account"])
            return public_ids.resolve(payload.get("kind"), payload.get("value"))
        except Denied as error:
            # Metadata lookup failures are not subscription failures. Authentication
            # and throttling above still reject with 403 before any lookup runs.
            return {"lookup_error": str(error)}

    @app.post("/v1/jobs/start")
    def start():
        device, _, payload = auth("auto_chat")
        return jobs.start(device, payload)

    @app.post("/v1/jobs/status")
    def status():
        device, _, _ = auth("auto_chat")
        return {"jobs": jobs.status(device)}

    @app.post("/v1/jobs/stop")
    def stop():
        # Device proof required; expired subscribers must still be able to stop their jobs.
        device, _, payload = store.authenticate(request.get_json(), request.path)
        jobs.stop(device, payload.get("panel"))
        return {"ok": True}

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="Private persistent directory, outside web roots")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    sub.add_parser("devices")
    grant = sub.add_parser("grant")
    grant.add_argument("device")
    grant.add_argument("--days", type=int, required=True)
    grant.add_argument("--features", required=True, help="all or comma-separated feature IDs")
    revoke = sub.add_parser("revoke")
    revoke.add_argument("device")
    group = sub.add_parser("import-group")
    group.add_argument("id")
    group.add_argument("name")
    group.add_argument("file")
    assign = sub.add_parser("assign")
    assign.add_argument("device")
    assign.add_argument("group")
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=5011)
    args = parser.parse_args()
    root = Path(args.data).resolve()
    if args.command == "init":
        root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            root.chmod(0o700)
        for name in ("signing.pem", "accounts.key"):
            if (root / name).exists():
                parser.error("Keys already exist; refusing to replace them.")
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with (root / "signing.pem").open("xb") as out:
            out.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with (root / "accounts.key").open("xb") as out:
            out.write(AESGCM.generate_key(bit_length=256))
        if os.name != "nt":
            (root / "signing.pem").chmod(0o600)
            (root / "accounts.key").chmod(0o600)
        print("Server public key (safe to include in APK):", b64(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
        Store(root)
        return
    store = Store(root)
    with store.db() as db:
        if args.command == "devices":
            for row in db.execute("SELECT id,features,expires,revoked FROM devices"):
                print(dict(row))
        elif args.command == "grant":
            features = FEATURES if args.features == "all" else set(args.features.split(","))
            if not features <= FEATURES or not features or args.days < 1 or args.days > 3660:
                parser.error("Invalid features or duration.")
            if db.execute("UPDATE devices SET features=?,expires=?,revoked=0,version=version+1 WHERE id=?", (json.dumps(sorted(features)), int(time.time()) + args.days * 86400, args.device)).rowcount != 1:
                parser.error("Unknown device. Activate from app first.")
        elif args.command == "revoke":
            db.execute("UPDATE devices SET revoked=1,active_until=0,version=version+1 WHERE id=?", (args.device,))
        elif args.command == "import-group":
            accounts = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))
            if not isinstance(accounts, list) or not 1 <= len(accounts) <= 64:
                parser.error("Group must contain 1–64 accounts.")
            from backend.room_credentials import gateway_credentials
            seen = set()
            for account in accounts:
                # Room Lite exports use user_session; backend uses oauth_token.
                if account.get("user_session") and not account.get("oauth_token") and not account.get("access_token"):
                    account["oauth_token"] = account["user_session"]
                uid, *_ = gateway_credentials(account)
                if uid in seen:
                    parser.error("Duplicate account.")
                seen.add(uid)
            nonce = secrets.token_bytes(12)
            encrypted = nonce + store.cipher.encrypt(nonce, encode(accounts), args.id.encode())
            db.execute("INSERT INTO groups VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,encrypted=excluded.encrypted,count=excluded.count", (args.id, args.name, encrypted, len(accounts)))
        elif args.command == "assign":
            if not db.execute("SELECT 1 FROM devices WHERE id=?", (args.device,)).fetchone() or not db.execute("SELECT 1 FROM groups WHERE id=?", (args.group,)).fetchone():
                parser.error("Unknown device or group.")
            db.execute("INSERT OR IGNORE INTO grants VALUES (?,?)", (args.device, args.group))
    if args.command == "serve":
        create_app(root).run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
