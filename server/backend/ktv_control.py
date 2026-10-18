"""Fixed KTV operations on the existing authenticated room socket.

No arbitrary opcode/UID/token input. A queue acknowledgement is not singing
permission: publication needs a fresh snapshot naming this authenticated user.
"""
import asyncio
import time
from . import room_protocol as p

JOIN, GET, QUIT, UPDATE = 0x02000104, 0x02000105, 0x02000106, 0x02000107
SONGS = (
    {'id':'611752105040384011', 'title':'Sukoon', 'duration':324},
    {'id':'611752105015201999', 'title':'Tu Jo Hai', 'duration':301},
    {'id':'611752105040742606', 'title':'Qubool', 'duration':285},
)


def entry(raw):
    f = p.fields(raw)
    title = p.first(f,3,b'')
    return dict(uid=p.first(f,1,0), song=p.first(f,2,0),
                title=title.decode('utf-8',errors='replace')[:500],
                duration=p.first(f,4,0), singing=p.first(f,5,0), raw=raw)


def snapshot(values):
    items = values.get(2, [])
    if len(items)>1000 or any(not isinstance(v,bytes) for v in items):
        raise ValueError('Invalid queue response')
    singer = p.fields(p.first(values,3,b''))
    return [entry(raw) for raw in items], dict(uid=p.first(singer,1,0),
        song=p.first(singer,2,0), duration=p.first(singer,4,0),
        elapsed=p.first(singer,5,0), status=p.first(singer,6,0),
        singing=p.first(singer,7,0))


class KtvControl:
    def __init__(self, service, uid):
        self.service, self.uid = service, uid
        self.pending_song = None
        self.items, self.singer = [], {}
        self.lock = asyncio.Lock()
        self.watching = False
        self.error = ''
        self.confirm_until = 0

    async def refresh(self):
        self.items, self.singer = snapshot(await self.service._request(GET,p.room_request(self.service._token)))
        # Joining explicitly requested singing when the upstream grants the turn.
        s = self.singer
        if self.pending_song and s['uid']==self.uid and s['song']==self.pending_song and s['singing']>0 and s['status']==0:
            await self.update(1,0)
            self.pending_song = None
            self.items, self.singer = snapshot(await self.service._request(GET,p.room_request(self.service._token)))
        if self.pending_song and time.monotonic()>self.confirm_until and not any(v['uid']==self.uid for v in self.items):
            self.pending_song=None
        self.watching=self.pending_song is not None or any(v['uid']==self.uid for v in self.items) or self.can_publish()
        return self.public()

    async def update(self, status, reason):
        s = self.singer
        if s.get('uid')!=self.uid or s.get('singing',0)<=0 or s.get('status') not in (0,1):
            raise ValueError('Authenticated account is not the singer')
        body = p.room_request(self.service._token)+p.integer(3,status)+p.integer(6,s['singing'])+p.integer(7,reason)
        await self.service._request(UPDATE,body)

    async def action(self, operation, song_id=None):
        async with self.lock:
            if operation in ('ktv.finish','ktv.leave'):
                self.pending_song=None
            await self.refresh()
            if operation=='ktv.join':
                song = next((v for v in SONGS if v['id']==song_id),None)
                if song is None:
                    raise ValueError('Choose an available catalog song')
                if any(v['uid']==self.uid for v in self.items) or self.singer.get('uid')==self.uid and self.singer.get('status') in (0,1):
                    raise ValueError('Already queued or singing')
                body=p.room_request(self.service._token)+p.integer(3,int(song['id']))+p.integer(4,song['duration'])+p.blob(5,song['title'])
                body+=p.integer(6,0)+p.integer(7,0)+p.integer(10,0)
                await self.service._request(JOIN,body)
                self.pending_song=int(song['id'])
                self.confirm_until=time.monotonic()+10
                self.watching=True
            elif operation in ('ktv.finish','ktv.leave'):
                self.pending_song=None
                if self.singer.get('uid')==self.uid and self.singer.get('status') in (0,1):
                    await self.update(2,1001)
                elif operation=='ktv.leave':
                    own=next((v for v in self.items if v['uid']==self.uid),None)
                    if own:
                        await self.service._request(QUIT,p.room_request(self.service._token)+p.blob(3,own['raw']))
            result=await self.refresh()
            self.watching=self.pending_song is not None or result['queued'] or result['singing']
            self.error=''
            return result

    def can_publish(self):
        return self.singer.get('uid')==self.uid and self.singer.get('singing',0)>0 and self.singer.get('status')==1

    def public(self):
        return {'error':self.error,'queued':any(v['uid']==self.uid for v in self.items),
                'singing':self.can_publish(),
                'singer_uid':str(self.singer.get('uid',0)),
                'elapsed':self.singer.get('elapsed',0),
                'duration':self.singer.get('duration',0),
                'entries':[{'uid':str(v['uid']), 'song':str(v['song']), 'title':v['title']} for v in self.items[:30]]}
