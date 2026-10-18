"""Thin-client API. All permissions, credentials and execution stay on server."""
import hashlib
import json
import threading
import time
import os

from flask import request
from licensing.service import Denied, encode
from licensing.jobs import Jobs
from licensing.remote_ledger import CommandLedger
from licensing.remote_rooms import RemoteRooms
from licensing.remote_accounts import RemoteAccounts, login


def fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or not value.keys() <= set(required) | set(optional):
        raise Denied('Invalid command fields.')


def number(value):
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal() or not 0 < int(value) < 2**63 or str(int(value)) != value:
        raise Denied('Use a positive decimal internal room ID.')
    return int(value)


class BackgroundJobStore:
    """Explicit bounded server-run consent, independent of phone UI lifetime."""
    def __init__(self, store):
        self.store = store
        self.deadlines = {}

    def __getattr__(self, name):
        return getattr(self.store, name)

    def job_permission(self, device, group):
        row = dict(self.store.job_permission(device, group, active=False))
        row['active_until'] = min(row['expires'], self.deadlines.get((device, group), 0))
        if row['active_until'] <= time.time():
            raise Denied('Server job duration expired.')
        return row


class RemoteController:
    def __init__(self, store, factory, public_ids, jobs=None):
        self.store = store
        try:
            self.connection_limit=int(os.environ.get('ROOMLITE_REMOTE_MAX_CONNECTIONS','32'))
        except ValueError:
            raise RuntimeError('ROOMLITE_REMOTE_MAX_CONNECTIONS must be an integer') from None
        if not 1<=self.connection_limit<=128:
            raise RuntimeError('ROOMLITE_REMOTE_MAX_CONNECTIONS must be between 1 and 128')
        self.job_store = BackgroundJobStore(store)
        self.jobs = jobs or Jobs(self.job_store, factory)
        # The admin dashboard and remote API must operate the very same jobs.
        self.jobs.store = self.job_store
        self.accounts = RemoteAccounts(store)
        self.rooms = RemoteRooms(store, factory, accounts=self.accounts)
        self.public_ids = public_ids
        self.ledger = CommandLedger(store)
        self.lock = threading.RLock()
        self.stop_only = {'room.stop', 'jobs.stop', 'all.stop'}
        self.features = {'room.join':'room', 'chat.send':'room', 'seat.take':'room',
                         'seat.apply':'room', 'seat.cancel':'room', 'jobs.start':'auto_chat',
                         'sid.resolve':'room'}
        self.features.update({op:'ktv' for op in ('ktv.join','ktv.refresh','ktv.finish','ktv.leave')})
        self.features.update({'account.login':None,'account.import':None,'account.forget':None})

    def state(self, device):
        row = self.store.permission(device, active=True)
        features = json.loads(row['features'])
        feature = 'room' if 'room' in features else 'auto_chat' if 'auto_chat' in features else None
        groups = self.store.groups(device, feature=feature) if feature else []
        return {'protocol':2, 'server_boot':self.ledger.boot, 'features':features, 'groups':groups,
                'rooms':self.rooms.status(device), 'jobs':self.jobs.status(device), 'accounts':self.accounts.metadata(device),
                'account_protocol':1,
                'capabilities':['room','chat','seats','auto_chat','sid_resolver','hybrid_audio','ktv','audio_route'],
                'ktv_songs':__import__('backend.ktv_control',fromlist=['SONGS']).SONGS,
                'unavailable':['public_room_resolver','live_catalog_search'],
                'limits':{'manual_rooms':4, 'total_connections':self.connection_limit, 'job_accounts':64, 'run_seconds':3600},
                'credentials_returned':False}

    def _admit(self, extra):
        room_rows = self.rooms.active()
        with self.jobs.lock:
            job_rows = [j for j in self.jobs.jobs.values() if j['running']]
        count = len(room_rows) + sum(len(j['uids']) for j in job_rows)
        used = {r['uid'] for r in room_rows}
        used.update(uid for j in job_rows for uid in j['uids'])
        if used & extra:
            raise Denied('Account already in use by a server session/job.')
        if count + len(extra) > self.connection_limit:
            raise Denied('Free-server connection capacity reached.')

    def command(self, device, command):
        fields(command, ('id','op','args'))
        op, args = command['op'], command['args']
        if not isinstance(op, str) or op not in self.features.keys() | self.stop_only:
            raise Denied('Unsupported operation. No native fallback exists.')
        if not isinstance(args, dict):
            raise Denied('Invalid arguments.')
        # Client-supplied "subscribed", "role" or "features" flags have no authority.
        # Stop remains available with valid device proof after expiry/revocation.
        if op not in self.stop_only:
            self.store.permission(device, self.features[op], True)
        now = int(time.time())
        if self.store.increment_limit('remote:' + device + ':' + str(now // 60), now + 120) > 60 and op not in self.stop_only:
            raise Denied('Command limit reached.')
        with self.lock:
            identity, previous = self.ledger.reserve(device, command)
            if previous is not None:
                return previous
        # Network waits must not block another request's Stop command.
        result = {'command_id':command['id'], 'command_status':'rejected', 'error':'Command rejected.'}
        try:
            result = dict(self._execute(device, op, args), command_id=command['id'], command_status='accepted')
            if result.get('outcome_unknown'):
                result.update(command_status='outcome_unknown', retry_allowed=False)
        except Denied as error:
            result['error'] = str(error)
        except Exception:
            # Never reflect upstream messages, credentials, payloads or URLs.
            result.update(command_status='outcome_unknown', error='Operation failed or outcome could not be confirmed.', retry_allowed=False)
        self.ledger.finish(identity, result)
        return result

    def _execute(self, device, op, args):
        if op.startswith('account.'):
            fields(args, ('slot','email','password') if op=='account.login' else ('slot','account') if op=='account.import' else ('slot',))
            slot=args['slot']; self.accounts.key(device,slot)
            with self.lock:
                if any(r['device']==device and r['group'] is None and r['index']==slot for r in self.rooms.active()):
                    raise Denied('Disconnect this account slot before replacing or forgetting it.')
            now=int(time.time())
            if op=='account.login' and self.store.increment_limit('login:'+device+':'+str(now//60),now+120)>5:
                raise Denied('Too many login attempts. Wait a minute before trying again.')
            if op=='account.login':
                if not isinstance(args['email'],str) or not 3<=len(args['email'])<=254 or '@' not in args['email'] or not isinstance(args['password'],str) or not 1<=len(args['password'])<=256:
                    raise Denied('Enter your account email and password.')
                account=login(args['email'],args['password'])
            elif op=='account.import':
                from licensing.remote_accounts import clean
                account=clean(args['account'])
            with self.lock:
                if any(r['device']==device and r['group'] is None and r['index']==slot for r in self.rooms.active()):
                    raise Denied('Disconnect this account slot before replacing or forgetting it.')
                if op=='account.forget':
                    self.accounts.forget(device,slot)
                    return {'account':{'slot':slot,'saved':False}}
                return {'account':self.accounts.save(device,slot,account)}
        if op.startswith('ktv.'):
            fields(args, ('session','song') if op=='ktv.join' else ('session',))
            if not isinstance(args['session'],str) or len(args['session'])!=32:
                raise Denied('Invalid session.')
            if op=='ktv.join':
                number(args['song'])
            return self.rooms.action(device,args['session'],op,args)
        if op in self.stop_only:
            if op == 'all.stop':
                fields(args, ())
                self.jobs.stop(device)
                self.rooms.stop(device)
            elif op == 'room.stop':
                fields(args, ('session',))
                self.rooms.stop(device, args['session'])
            else:
                fields(args, (), ('panel',))
                panel = args.get('panel')
                if panel is not None and (type(panel) is not int or panel not in range(4)):
                    raise Denied('Invalid panel.')
                self.jobs.stop(device, panel)
            return {'stop_requested':True, 'cleanup_confirmed':False}
        if op == 'sid.resolve':
            fields(args, ('sid',))
            return {'result':self.public_ids.resolve('sid', str(number(args['sid'])))}
        if op == 'room.join':
            if 'slot' in args:
                fields(args, ('slot','room','run_seconds'), ('password',))
                room=number(args['room']); seconds=args['run_seconds']; slot=args['slot']
                self.accounts.key(device,slot)
                if type(seconds) is not int or not 60<=seconds<=3600 or not isinstance(args.get('password',''),str) or len(args.get('password',''))>256:
                    raise Denied('Invalid room password or session duration.')
                with self.lock:
                    account=self.accounts.get(device,slot)
                    from backend.room_credentials import gateway_credentials
                    self._admit({gateway_credentials(account)[0]})
                    return self.rooms.start(device,None,slot,account,room,args.get('password',''),seconds)
            fields(args, ('group','index','room','run_seconds'), ('password',))
            room = number(args['room'])
            seconds = args['run_seconds']
            index = args['index']
            if type(seconds) is not int or not 60 <= seconds <= 3600 or type(index) is not int or not 0 <= index < 64:
                raise Denied('Invalid account index or session duration.')
            if not isinstance(args['group'], str) or not isinstance(args.get('password',''), str) or len(args.get('password','')) > 256:
                raise Denied('Invalid group or room password.')
            self.store.job_permission(device, args['group'], feature='room')
            accounts = self.store.accounts(device, args['group'], feature='room')
            if index >= len(accounts):
                raise Denied('Account not available in assigned group.')
            from backend.room_credentials import gateway_credentials
            account = accounts[index]
            with self.lock:
                self._admit({gateway_credentials(account)[0]})
                return self.rooms.start(device, args['group'], index, account, room, args.get('password',''), seconds)
        if op in ('chat.send','seat.take','seat.apply','seat.cancel'):
            expected = ('session','text') if op == 'chat.send' else ('session','seat') if op == 'seat.take' else ('session',)
            fields(args, expected)
            if not isinstance(args['session'], str) or len(args['session']) != 32:
                raise Denied('Invalid session.')
            if op == 'chat.send' and (not isinstance(args['text'], str) or not args['text'].strip() or len(args['text']) > 1000):
                raise Denied('Message must contain 1-1000 characters.')
            if op == 'seat.take' and (type(args['seat']) is not int or not 0 < args['seat'] <= 10000):
                raise Denied('Invalid seat.')
            return self.rooms.action(device, args['session'], op, args)
        if op == 'jobs.start':
            fields(args, ('panel','group','room','messages','delay_ms','rounds','run_seconds'), ('password',))
            if type(args['run_seconds']) is not int or not 60 <= args['run_seconds'] <= 3600:
                raise Denied('Choose a server run duration of 60-3600 seconds.')
            room = number(args['room'])
            self.store.job_permission(device, args['group'])
            accounts = self.store.accounts(device, args['group'])
            if not 1 <= len(accounts) <= 64:
                raise Denied('Account group must contain 1–64 accounts.')
            from backend.room_credentials import gateway_credentials
            with self.lock:
                self._admit({gateway_credentials(a)[0] for a in accounts})
                self.job_store.deadlines[device, args['group']] = time.time() + args['run_seconds']
                payload = {key:value for key,value in args.items() if key != 'run_seconds'}
                payload['room'] = room
                return self.jobs.start(device, payload)
        raise Denied('Unsupported operation.')

    def close(self):
        with self.jobs.lock:
            devices = {job['device'] for job in self.jobs.jobs.values()}
        for device in devices:
            self.jobs.stop(device)
        self.rooms.close()


def register_remote(app, factory, public_ids):
    controller = RemoteController(app.extensions['license_store'], factory, public_ids, app.extensions['license_jobs'])
    app.extensions['remote'] = controller

    @app.before_request
    def remote_only():
        if request.path.startswith('/v1/') and request.path not in ('/v1/challenge','/v1/lease'):
            raise Denied('This deployment accepts server-controlled remote commands only.')

    @app.post('/v2/remote/state')
    def state():
        device, _, _ = controller.store.authenticate(request.get_json(), request.path)
        return controller.state(device)

    @app.post('/v2/remote/command')
    def command():
        device, _, payload = controller.store.authenticate(request.get_json(), request.path)
        return controller.command(device, payload)

    @app.post('/v2/remote/audio')
    def audio():
        device, _, payload=controller.store.authenticate(request.get_json(),request.path)
        fields(payload,('session','mode'),('source','ktv'))
        controller.store.permission(device,'audio',True)
        mode=payload['mode']
        if mode not in ('listen','publish') or not isinstance(payload['session'],str) or len(payload['session'])!=32:
            raise Denied('Invalid audio request.')
        source=payload.get('source')
        if source is not None:
            if not isinstance(source,str) or len(source)!=32:
                raise Denied('Invalid route source.')
            controller.store.permission(device,'audio_target',True)
        if 'ktv' in payload and type(payload['ktv']) is not bool:
            raise Denied('Invalid KTV mode.')
        now=int(time.time())
        if controller.store.increment_limit('audio:'+device+':'+str(now//60),now+120)>60:
            raise Denied('Audio renewal limit reached.')
        result=controller.rooms.audio(device,payload['session'],mode,source,payload.get('ktv',False))
        row=controller.store.permission(device,'audio',True)
        if source:
            controller.store.permission(device,'audio_target',True)
        if payload.get('ktv',False):
            controller.store.permission(device,'ktv',True)
        result['valid_for_ms']=max(0,min(5000,int((min(row['expires'],row['active_until'])-time.time())*1000)))
        features=json.loads(row['features'])
        result.update(music='music' in features,effects='effects' in features)
        return result
