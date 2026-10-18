"""Atlas persistence. TLS, atomic challenge consumption, encrypted accounts and sealed keys."""
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import secrets
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError
from licensing.service import Store, Denied, LEASE_SECONDS, REMOTE_ACTIONS, b64, unb64, encode


def expiry(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc)


class MongoStore(Store):
    @classmethod
    def from_environment(cls):
        uri = os.environ.get("MONGODB_URI", "")
        database = os.environ.get("MONGODB_DATABASE", "roomlite_control")
        master = os.environ.get("ROOMLITE_MASTER_SECRET", "")
        if len(master) < 32:
            raise RuntimeError("Set ROOMLITE_MASTER_SECRET to a stable random secret of at least 32 characters.")
        if not uri.startswith("mongodb+srv://") or len(uri) > 4096 or "<" in uri or ">" in uri:
            raise RuntimeError("Set a valid Atlas SRV connection URI privately in MONGODB_URI.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,38}", database):
            raise RuntimeError("MONGODB_DATABASE must be a valid application database name.")
        try:
            client = MongoClient(uri, tls=True, tlsAllowInvalidCertificates=False, tlsAllowInvalidHostnames=False,
                                 serverSelectionTimeoutMS=10000, connectTimeoutMS=10000, socketTimeoutMS=15000,
                                 maxPoolSize=20, retryWrites=True, appname="RajputEliteControl")
            client.admin.command("ping")
            return cls(client, database, master)
        except Exception:
            # Driver exception text may include host/user/URI details. Never propagate it to logs.
            raise RuntimeError("Atlas initialization failed. Check credentials, IP access, permissions and the original master secret.") from None

    def __init__(self, client, database, master):
        if len(master) < 32:
            raise RuntimeError("Master secret is too short.")
        self.client = client
        self.mongo = client[database]
        self.mongo.challenges.create_index("nonce", unique=True)
        self.mongo.challenges.create_index("delete_after", expireAfterSeconds=0)
        self.mongo.limits.create_index("delete_after", expireAfterSeconds=0)
        self.mongo.audit.create_index("time")
        # One stable environment secret protects all private keys stored in Atlas.
        seal = AESGCM(hashlib.sha256(master.encode()).digest())
        aad = ("RoomLite keys v1:" + database).encode()
        sealed = self.mongo.settings.find_one({"_id": "sealed_keys_v1"})
        if sealed is None:
            signer = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            material = {"signing": b64(signer.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
                        "accounts": b64(AESGCM.generate_key(bit_length=256)), "session": secrets.token_urlsafe(48)}
            nonce = secrets.token_bytes(12)
            blob = nonce + seal.encrypt(nonce, encode(material), aad)
            try:
                self.mongo.settings.insert_one({"_id": "sealed_keys_v1", "encrypted": blob})
            except DuplicateKeyError:
                pass  # Another first-start worker won initialization; load its keys.
            sealed = self.mongo.settings.find_one({"_id": "sealed_keys_v1"})
        try:
            blob = bytes(sealed["encrypted"])
            material = json.loads(seal.decrypt(blob[:12], blob[12:], aad))
            self.signer = serialization.load_der_private_key(unb64(material["signing"]), None)
            self.cipher = AESGCM(unb64(material["accounts"]))
            self.admin_secret = material["session"]
        except Exception:
            raise RuntimeError("Cannot unlock stored server keys. Restore the original ROOMLITE_MASTER_SECRET; keys were not replaced.") from None

    @staticmethod
    def row(doc):
        if doc is None:
            return None
        return {"id": doc["_id"], "public_key": doc.get("public_key", ""), "features": json.dumps(doc.get("features", [])),
                "expires": doc.get("expires", 0), "revoked": doc.get("revoked", 0),
                "active_until": doc.get("active_until", 0), "version": doc.get("version", 0)}

    def increment_limit(self, bucket, expires):
        doc = self.mongo.limits.find_one_and_update({"_id": bucket},
            {"$inc": {"count": 1}, "$setOnInsert": {"delete_after": expiry(expires)}}, upsert=True, return_document=ReturnDocument.AFTER)
        return doc["count"]

    def challenge(self, public_key, action, digest):
        if not isinstance(action, str) or action not in {"/v1/lease", "/v1/groups", "/v1/jobs/start", "/v1/jobs/status", "/v1/jobs/stop", "/v1/resolve"} | REMOTE_ACTIONS:
            raise Denied("Unsupported action.")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or not isinstance(public_key, str):
            raise Denied("Invalid request digest or device key.")
        der = unb64(public_key)
        key = serialization.load_der_public_key(der)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise Denied("Unsupported device key.")
        device, nonce, now = hashlib.sha256(der).hexdigest(), secrets.token_urlsafe(32), int(time.time())
        self.mongo.devices.update_one({"_id": device}, {"$setOnInsert": {"public_key": public_key, "features": [],
            "expires": 0, "revoked": 0, "active_until": 0, "version": 0, "groups": [], "created": now}}, upsert=True)
        # Fixed atomic slots allow concurrent UI/media proofs without permitting
        # an unbounded outstanding challenge set or invalidating in-flight work.
        for slot in range(8):
            identity=device+":"+action+":"+str(slot)
            try:
                self.mongo.challenges.replace_one({"_id":identity,"expires":{"$lte":now}},
                    {"device":device,"nonce":nonce,"action":action,"digest":digest,
                     "expires":now+60,"delete_after":expiry(now+60)},upsert=True)
                return {"device":device,"nonce":nonce,"expires":now+60}
            except DuplicateKeyError:
                continue
        raise Denied("Too many pending device proofs. Wait for expiry.")

    def authenticate(self, body, action):
        if not isinstance(body, dict) or any(not isinstance(body.get(field), str) for field in ("device", "nonce", "payload", "signature")):
            raise Denied("Invalid device proof.")
        device, nonce = body["device"], body["nonce"]
        if not re.fullmatch(r"[0-9a-f]{64}", device) or not 20 <= len(nonce) <= 100:
            raise Denied("Invalid device proof.")
        raw = unb64(body["payload"])
        if len(raw) > 20000:
            raise Denied("Request too large.")
        digest = hashlib.sha256(raw).hexdigest()
        query = {"nonce": nonce, "device": device, "action": action, "digest": digest, "expires": {"$gt": time.time()}}
        row = self.mongo.challenges.find_one(query)
        account = self.mongo.devices.find_one({"_id": device})
        if row is None or account is None:
            raise Denied("Challenge expired or invalid.")
        key = serialization.load_der_public_key(unb64(account["public_key"]))
        key.verify(unb64(body["signature"]), (device + "\n" + nonce + "\n" + action + "\n" + digest).encode(), ec.ECDSA(hashes.SHA256()))
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise Denied("Invalid payload.")
        # Atomic consumption after verification: concurrent/replayed copies cannot both succeed.
        if self.mongo.challenges.find_one_and_delete(query) is None:
            raise Denied("Challenge already consumed.")
        return device, nonce, payload

    def permission(self, device, feature=None, active=False):
        row = self.row(self.mongo.devices.find_one({"_id": device}))
        return self.check_permission(row, feature, active)

    def job_permission(self, device, group, feature="auto_chat", active=True):
        owner = self.mongo.devices.find_one({"_id": device})
        row = self.check_permission(self.row(owner), feature, active)
        if group not in owner.get("groups", []) or self.mongo.groups.find_one({"_id": group}, {"_id": 1}) is None:
            raise Denied("Account group access revoked.")
        return row

    def lease(self, device, nonce):
        row = self.permission(device)
        now = int(time.time())
        until = min(now + LEASE_SECONDS, row["expires"])
        updated = self.mongo.devices.update_one({"_id": device, "version": row["version"], "revoked": 0, "expires": {"$gt": now}}, {"$set": {"active_until": until}})
        if not updated.matched_count:
            raise Denied("Subscription changed. Check again.")
        raw = encode({"device": device, "nonce": nonce, "iat": now, "exp": until,
                      "features": json.loads(row["features"]), "version": row["version"]})
        return {"payload": b64(raw), "signature": b64(self.signer.sign(raw, padding.PKCS1v15(), hashes.SHA256()))}

    def groups(self, device, feature="auto_chat"):
        self.permission(device, feature, True)
        owner = self.mongo.devices.find_one({"_id": device}, {"groups": 1})
        return [{"id": doc["_id"], "name": doc["name"], "count": doc["count"]}
                for doc in self.mongo.groups.find({"_id": {"$in": owner.get("groups", [])}}, {"name": 1, "count": 1}).sort("_id", 1)]

    def accounts(self, device, group, feature="auto_chat"):
        self.permission(device, feature, True)
        if not isinstance(group, str):
            raise Denied("Invalid group.")
        owner = self.mongo.devices.find_one({"_id": device}, {"groups": 1})
        row = self.mongo.groups.find_one({"_id": group}) if group in owner.get("groups", []) else None
        if row is None:
            raise Denied("Account group is not assigned to this device.")
        blob = bytes(row["encrypted"])
        return json.loads(self.cipher.decrypt(blob[:12], blob[12:], group.encode()))

    def save_group(self, group, name, encrypted, count):
        self.mongo.groups.replace_one({"_id": group}, {"name": name, "encrypted": encrypted, "count": count}, upsert=True)

    def init_audit(self):
        pass

    def record_audit(self, action, target):
        self.mongo.audit.insert_one({"time": int(time.time()), "action": action, "target": target})
        tail = list(self.mongo.audit.find({}, {"_id": 1}).sort("_id", -1).skip(2000).limit(100))
        if tail:
            self.mongo.audit.delete_many({"_id": {"$in": [doc["_id"] for doc in tail]}})

    def overview_rows(self):
        docs = list(self.mongo.devices.find({}, {"public_key": 0}).sort("created", -1).limit(1000))
        devices = [{key: value for key, value in self.row(doc).items() if key != "public_key"} for doc in docs]
        groups = [{"id": doc["_id"], "name": doc["name"], "count": doc["count"]} for doc in self.mongo.groups.find({}, {"name": 1, "count": 1}).sort("name", 1)]
        grants = [{"device": doc["_id"], "group_id": group} for doc in docs for group in doc.get("groups", [])]
        audit = [{"time": doc["time"], "action": doc["action"], "target": doc["target"]} for doc in self.mongo.audit.find().sort("_id", -1).limit(100)]
        return devices, groups, grants, audit

    def set_subscription(self, device, features, days, extend):
        for _ in range(5):
            doc = self.mongo.devices.find_one({"_id": device})
            if doc is None:
                raise Denied("Unknown device. Activate it from the phone first.")
            base = max(int(time.time()), doc["expires"]) if extend else int(time.time())
            result = self.mongo.devices.update_one({"_id": device, "version": doc["version"]}, {"$set": {"features": sorted(features),
                "expires": base + days * 86400, "revoked": 0, "active_until": 0}, "$inc": {"version": 1}})
            if result.matched_count:
                return
        raise Denied("Subscription changed concurrently. Retry.")

    def revoke_device(self, device):
        if not self.mongo.devices.update_one({"_id": device}, {"$set": {"revoked": 1, "active_until": 0}, "$inc": {"version": 1}}).matched_count:
            raise Denied("Unknown device.")

    def assign_groups(self, device, selected):
        known = {doc["_id"] for doc in self.mongo.groups.find({"_id": {"$in": selected}}, {"_id": 1})}
        if not set(selected) <= known:
            raise Denied("Unknown account group.")
        if not self.mongo.devices.update_one({"_id": device}, {"$set": {"groups": sorted(set(selected))}}).matched_count:
            raise Denied("Unknown device.")

    def health(self):
        return self.client.admin.command("ping").get("ok") == 1
