"""Four device-owned login slots. Only public metadata leaves the server."""
import json
import os
import threading
import uuid
import urllib.parse
import urllib.request
from licensing.service import Denied, encode


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def login(email, password):
    """Same email login as the previous Android app, executed only on server."""
    body = urllib.parse.urlencode(dict(x_auth_mode='email_login', x_auth_email=email.strip(), x_auth_password=password)).encode()
    req = urllib.request.Request('https://api.starmakerdesi.com/web/login', data=body,
        headers={'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
                 'Accept':'application/json','Origin':'https://www.starmakerdesi.com',
                 'Referer':'https://www.starmakerdesi.com/','country':'in','x-locale':'en'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=15) as response:
            raw=response.read(1024*1024+1)
            if response.status != 200 or len(raw)>1024*1024:
                raise ValueError()
        value=json.loads(raw)
        data=value.get('data') if isinstance(value.get('data'),dict) else {}
        user=value.get('user') if isinstance(value.get('user'),dict) else {}
        def pick(*values):
            return next((str(v) for v in values if v is not None and str(v) not in ('','null')), '')
        account=dict(uid=pick(value.get('id'),user.get('id'),data.get('uid'),data.get('id'),value.get('uid')),
            name=pick(value.get('stage_name'),user.get('stage_name'),value.get('name'),user.get('name'),data.get('name')),
            oauth_token=pick(value.get('oauth_token'),data.get('oauth_token'),value.get('auth_token'),data.get('auth_token')),
            oauth_token_secret=pick(value.get('oauth_token_secret'),data.get('oauth_token_secret'),value.get('auth_key'),data.get('auth_key')),
            device_id=uuid.uuid4().hex, oauth_version='v1')
        return clean(account)
    except Exception:
        raise Denied('Login was not completed. Check the email/password or finish verification in the official app. No automatic retry.') from None


def clean(value):
    from backend.room_credentials import gateway_credentials
    if not isinstance(value,dict):
        raise Denied('Invalid saved account file.')
    allowed=('uid','id','name','stage_name','oauth_version','oauth_token','oauth_token_secret',
             'access_token','device_id','gateway_user_token','gateway_token')
    account={key:value[key] for key in allowed if key in value}
    if any(not isinstance(v,(str,int)) or isinstance(v,bool) or len(str(v))>4096 for v in account.values()):
        raise Denied('Invalid account fields.')
    try:
        uid,_,_,_=gateway_credentials(account)
        if not 0<uid<2**63:
            raise ValueError()
    except Exception:
        raise Denied('Account is missing a valid UID, login token or device ID.') from None
    account['uid']=uid
    account['name']=str(account.get('name') or account.get('stage_name') or 'Account')[:80]
    return account


class RemoteAccounts:
    def __init__(self, store):
        self.store=store
        self.lock=threading.RLock()
        if not hasattr(store,'mongo'):
            with store.db() as db:
                db.execute('CREATE TABLE IF NOT EXISTS remote_accounts (id TEXT PRIMARY KEY, encrypted BLOB NOT NULL)')

    def key(self, device, slot):
        if type(slot) is not int or slot not in range(4):
            raise Denied('Choose account slot 1–4.')
        return device+':'+str(slot)

    def get(self, device, slot):
        key=self.key(device,slot)
        if hasattr(self.store,'mongo'):
            row=self.store.mongo.remote_accounts.find_one({'_id':key})
        else:
            with self.store.db() as db:
                row=db.execute('SELECT encrypted FROM remote_accounts WHERE id=?',(key,)).fetchone()
        if row is None:
            raise Denied('Log in to this account slot first.')
        blob=bytes(row['encrypted'])
        return json.loads(self.store.cipher.decrypt(blob[:12],blob[12:],key.encode()))

    def save(self, device, slot, account):
        self.store.permission(device,active=True)
        key=self.key(device,slot)
        account=clean(account)
        nonce=os.urandom(12)
        blob=nonce+self.store.cipher.encrypt(nonce,encode(account),key.encode())
        with self.lock:
            if hasattr(self.store,'mongo'):
                self.store.mongo.remote_accounts.replace_one({'_id':key},{'encrypted':blob},upsert=True)
            else:
                with self.store.db() as db:
                    db.execute('INSERT OR REPLACE INTO remote_accounts VALUES (?,?)',(key,blob))
        return self.public(account,slot)

    def forget(self, device, slot):
        key=self.key(device,slot)
        with self.lock:
            if hasattr(self.store,'mongo'):
                self.store.mongo.remote_accounts.delete_one({'_id':key})
            else:
                with self.store.db() as db:
                    db.execute('DELETE FROM remote_accounts WHERE id=?',(key,))

    def public(self, account, slot):
        return dict(slot=slot,uid=str(account['uid']),name=account['name'],saved=True)

    def metadata(self, device):
        result=[]
        for slot in range(4):
            try:
                result.append(self.public(self.get(device,slot),slot))
            except Denied:
                result.append(dict(slot=slot,saved=False))
        return result
