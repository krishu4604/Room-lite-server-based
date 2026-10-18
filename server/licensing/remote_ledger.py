"""Durable idempotency without storing command arguments or credentials."""
from datetime import datetime, timezone
import hashlib
import json
import time
import uuid

from licensing.service import Denied, encode


class CommandLedger:
    def __init__(self, store):
        self.store = store
        self.boot = uuid.uuid4().hex
        if hasattr(store, 'mongo'):
            store.mongo.remote_commands.create_index('delete_after', expireAfterSeconds=0)
        else:
            with store.db() as db:
                db.execute('CREATE TABLE IF NOT EXISTS remote_commands (id TEXT PRIMARY KEY, digest TEXT NOT NULL, boot TEXT NOT NULL, result TEXT, expires INTEGER NOT NULL)')

    def reserve(self, device, command):
        key = command.get('id')
        if not isinstance(key, str) or not 16 <= len(key) <= 80 or not all(c.isascii() and (c.isalnum() or c in '-_') for c in key):
            raise Denied('Invalid command id.')
        identity = device + ':' + key
        digest = hashlib.sha256(encode(command)).hexdigest()
        now = int(time.time())
        expires = now + 86400
        if hasattr(self.store, 'mongo'):
            from pymongo.errors import DuplicateKeyError
            fresh = dict(_id=identity, digest=digest, boot=self.boot, result=None,
                         expires=expires, delete_after=datetime.fromtimestamp(expires, timezone.utc))
            try:
                self.store.mongo.remote_commands.insert_one(fresh)
                return identity, None
            except DuplicateKeyError:
                row = self.store.mongo.remote_commands.find_one({'_id': identity})
        else:
            with self.store.db() as db:
                db.execute('BEGIN IMMEDIATE')
                # Never drop uncertain commands merely to make a retry execute.
                row = db.execute('SELECT * FROM remote_commands WHERE id=?', (identity,)).fetchone()
                if row is None:
                    db.execute('INSERT INTO remote_commands VALUES (?,?,?,?,?)', (identity, digest, self.boot, None, expires))
                    return identity, None
                row = dict(row)
        if row is None or row['digest'] != digest:
            raise Denied('Command id already used with different arguments.')
        if row['result'] is not None:
            result = row['result'] if isinstance(row['result'], dict) else json.loads(row['result'])
            if row['boot'] != self.boot and command['op'] not in ('sid.resolve',):
                return identity, {'command_id':key, 'command_status':'outcome_unknown',
                                  'duplicate':True, 'retry_allowed':False,
                                  'server_restarted':True,
                                  'error':'Historical receipt only. Live session state was lost after restart; verify before a new action.'}
            return identity, dict(result, duplicate=True)
        return identity, {'command_id': key, 'command_status': 'executing' if row['boot'] == self.boot else 'outcome_unknown', 'retry_allowed': False}

    def finish(self, identity, result):
        if hasattr(self.store, 'mongo'):
            self.store.mongo.remote_commands.update_one({'_id': identity, 'boot': self.boot}, {'$set': {'result': result}})
        else:
            with self.store.db() as db:
                db.execute('UPDATE remote_commands SET result=? WHERE id=? AND boot=?', (json.dumps(result), identity, self.boot))
