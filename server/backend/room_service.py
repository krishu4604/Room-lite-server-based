"""Single authenticated room session. No MQTT, HTTP chat fallback, or audio bridge."""
import asyncio
import contextlib
import logging
import struct
import time
import uuid
from collections import deque

from . import room_protocol as p
from .room_credentials import gateway_credentials

logger = logging.getLogger(__name__)


class RoomService:
    def __init__(self, connect_timeout=10, request_timeout=12, leave_timeout=3):
        self._connect_timeout = connect_timeout
        self._request_timeout = request_timeout
        self._leave_timeout = leave_timeout
        self._lifecycle = asyncio.Lock()
        self._writes = asyncio.Lock()
        self._writer = None
        self._reader_task = None
        self._heartbeat_task = None
        self._pending = {}
        self._sequence = 0
        self._token = b''
        self.state = 'disconnected'
        self.error = ''
        self.room_id = 0
        self.uid = 0
        self.nickname = ''
        self.online_users = 0
        self.seat_id = None
        self.session_id = ''
        self._events = deque(maxlen=200)
        self._event_id = 0
        self.seat_application = 'idle'
        self._application_id = None
        self._approval_task = None
        self._approval_cursor = 0
        self._owner_loop = None

    def _fail(self, stage, error):
        # Keep the first cause: closing the writer also wakes the reader with EOF.
        if self.state == 'failed':
            return
        codes = {
            'invalid gateway frame header': 'INVALID_HEADER',
            'invalid gateway header': 'INVALID_HEADER',
            'invalid gateway length': 'INVALID_LENGTH',
            'truncated header': 'TRUNCATED_HEADER',
            'gateway checksum mismatch': 'CHECKSUM_MISMATCH',
            'invalid gateway envelope': 'INVALID_ENVELOPE',
            'unsupported gateway compression': 'UNSUPPORTED_COMPRESSION',
            'invalid or oversized gzip payload': 'INVALID_GZIP',
            'invalid protobuf field': 'INVALID_PROTOBUF',
            'truncated protobuf field': 'TRUNCATED_PROTOBUF',
            'truncated fixed-width field': 'TRUNCATED_PROTOBUF',
            'truncated varint': 'TRUNCATED_VARINT',
            'varint overflow': 'VARINT_OVERFLOW',
            'unsupported protobuf wire type': 'UNSUPPORTED_WIRE_TYPE',
        }
        if isinstance(error, asyncio.IncompleteReadError):
            code = 'TRUNCATED_READ' if error.partial else 'EOF'
        elif isinstance(error, TimeoutError):
            code = 'TIMEOUT'
        elif isinstance(error, OSError):
            code = 'NETWORK_ERROR'
        else:
            code = codes.get(str(error), 'PROCESSING_ERROR')
        self.state = 'failed'
        self.error = 'Gateway session failed [%s / %s]. Reconnect.' % (stage, code)
        self._token = b''
        self.seat_id = None
        self.online_users = 0
        self._reset_application()
        for _, future in list(self._pending.values()):
            if not future.done():
                future.set_exception(ValueError(self.error))
        if self._writer:
            self._writer.close()
        logger.warning('Room gateway failure stage=%s code=%s', stage, code)
        self._event('status', text=self.error)

    def send_chat_from_thread(self, text, timeout=15):
        """Bridge a synchronous worker onto the loop that owns the room socket."""
        loop = self._owner_loop
        if loop is None or loop.is_closed() or not loop.is_running():
            raise ValueError('room session event loop is unavailable')
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            raise ValueError('use async send_chat on the room session event loop')
        coroutine = self.send_chat(text, _session_id=self.session_id)
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        except RuntimeError:
            coroutine.close()
            raise ValueError('room session event loop is unavailable') from None
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            future.cancel()
            raise

    def _event(self, kind, **details):
        self._event_id += 1
        self._events.append({'id': self._event_id, 'kind': kind, 'time': time.time(), **details})

    def status(self):
        return {'state': self.state, 'joined': self.state == 'joined', 'error': self.error,
                'room_id': self.room_id, 'account_uid': str(self.uid), 'nickname': self.nickname,
                'online_users': self.online_users, 'seat_id': self.seat_id,
                'seat_application': self.seat_application,
                'session_id': self.session_id, 'events': list(self._events),
                'audio_available': False}

    async def _request(self, opcode, payload, timeout=None):
        if timeout is None:
            timeout = self._request_timeout
        if not self._writer or self._writer.is_closing():
            raise ValueError('gateway is disconnected')
        self._sequence += 1
        sequence = self._sequence
        future = asyncio.get_running_loop().create_future()
        self._pending[sequence] = (opcode, future)
        try:
            async with self._writes:
                self._writer.write(p.encode_frame(self.uid, opcode, payload, sequence))
                await self._writer.drain()
            frame = await asyncio.wait_for(future, timeout)
            if opcode == p.JOIN_SEAT and frame.status != 0:
                if frame.status == 2:
                    # Native GatewayTransportManager decodes the protobuf body
                    # for status 2 (logic failure), not a transport/token error.
                    values = p.fields(frame.payload)
                    base = p.fields(p.first(values, 1, b''))
                    code = p.first(base, 1)
                    if isinstance(code, int):
                        code &= 0xFFFFFFFF
                        code = code if code < 2**31 else code - 2**32
                        raise ValueError('Seat %s rejected by room (application code %s; gateway status 2).'
                                         % (p.first(p.fields(payload), 3), code))
                    raise ValueError('Seat request rejected by room (gateway status 2; no application code).')
                signed_status = frame.status if frame.status < 2**31 else frame.status - 2**32
                raise ValueError('Seat %s rejected by gateway (status %s / 0x%08X).'
                                 % (p.first(p.fields(payload), 3), signed_status, frame.status))
            return p.response_fields(frame)
        finally:
            self._pending.pop(sequence, None)

    async def _read(self, reader):
        stage = 'READ_HEADER'
        try:
            while True:
                stage = 'READ_HEADER'
                header = await reader.readexactly(12)
                magic, kind, length = struct.unpack('>III', header)
                if magic != p.MAGIC or kind not in (1, 2, 3) or not 32 <= length <= p.MAX_FRAME - 12:
                    raise ValueError('invalid gateway frame header')
                stage = 'READ_BODY'
                body = await reader.readexactly(length)
                stage = 'DECODE_FRAME'
                frame = p.decode_frame(header + body)
                if frame.kind == 2:
                    entry = self._pending.get(frame.sequence)
                    if entry and entry[0] == frame.opcode and not entry[1].done():
                        entry[1].set_result(frame)
                elif frame.kind == 3 and frame.opcode == p.CHAT:
                    stage = 'CHAT_PUSH'
                    approval = p.approval_event(frame.payload)
                    if approval:
                        self._receive_approval(approval)
                    event = p.chat_event(frame.payload)
                    if event and event['room_id'] == self.room_id:
                        self._event('chat', **event)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self._fail(stage, error)

    async def _heartbeats(self):
        try:
            while self.state == 'joined':
                await asyncio.sleep(20)
                if self.state != 'joined':
                    return
                await self._request(p.HEARTBEAT, p.room_request(self._token))
                await self._request(p.GATEWAY_PING, b'')
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self._fail('HEARTBEAT', error)

    async def _close(self):
        self._owner_loop = None
        self._token = b''
        self._reset_application()
        if self._approval_task:
            self._approval_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._approval_task
            self._approval_task = None
        for task in (self._heartbeat_task, self._reader_task):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        for _, future in list(self._pending.values()):
            if not future.done():
                future.set_exception(ValueError('room session stopped'))
        self._pending.clear()
        if self._writer:
            self._writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._writer.wait_closed(), 2)
        self._writer = self._reader_task = self._heartbeat_task = None
        self.seat_id = None

    async def join(self, room_id, account, password=''):
        async with self._lifecycle:
            if self.state in ('connecting', 'authenticating', 'joining', 'joined'):
                raise ValueError('leave the current room before joining another')
            uid, session, token, device = gateway_credentials(account)
            await self._close()
            self._owner_loop = asyncio.get_running_loop()
            self.session_id = uuid.uuid4().hex
            self._events.clear()
            self._event_id = 0
            self._sequence = 0
            self._approval_cursor = 0
            self.room_id, self.uid = room_id, uid
            self.nickname = account.get('user_name') or account.get('nickname') or 'User'
            self.online_users, self.error = 0, ''
            self.state = 'connecting'
            try:
                reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection('sg-front.starmakerstudios.com', 20000), self._connect_timeout)
                self._reader_task = asyncio.create_task(self._read(reader))
                self.state = 'authenticating'
                login = (p.blob(1, b'') + p.integer(2, uid) + (p.blob(3, token) if token else b'') +
                         p.integer(4, int(account.get('gateway_app_version') or 486960877)) +
                         p.blob(5, device) + p.blob(6, session) +
                         p.blob(7, account.get('gateway_app_name') or 'tvp') +
                         p.blob(8, account.get('gateway_version_name') or '9.12.3') +
                         p.integer(9, 2) + p.blob(10, account.get('os_version') or '15') +
                         p.blob(11, account.get('os_info') or 'Android'))
                await self._request(p.LOGIN, login)
                self.state = 'joining'
                join = (p.blob(1, b'') + p.integer(2, room_id) + p.blob(3, password) +
                        p.blob(4, self.nickname) + p.blob(5, '9.12.3') +
                        p.blob(6, 'tvp') + p.blob(7, 'android') +
                        p.blob(9, 'zorro') + p.blob(10, 'voicechat') +
                        p.blob(11, str(room_id)) + p.blob(12, 'native_my-rooms') +
                        p.blob(16, p.blob(1, device) + p.blob(2, account.get('country') or 'in') +
                               p.blob(3, account.get('os_info') or 'Android')))
                reply = await self._request(p.JOIN, join)
                room_token = p.first(reply, 2, b'')
                if not isinstance(room_token, bytes) or not room_token:
                    raise ValueError('join response did not provide a room token')
                self._token = room_token
                self.online_users = p.first(reply, 6, 0)
                self.state = 'joined'
                self._event('status', text='Room entry acknowledged by server.')
                self._heartbeat_task = asyncio.create_task(self._heartbeats())
                return self.status()
            except Exception:
                failure = self.error if self.state == 'failed' and self.error else 'Room login/join failed or timed out. Refresh the selected account login and retry.'
                await self._close()
                self.state = 'failed'
                self.error = failure
                raise ValueError(self.error) from None

    async def abort(self):
        """Explicit worker cancellation: close without waiting for a leave ACK."""
        async with self._lifecycle:
            await self._close()
            self.state, self.error = 'disconnected', ''
            self.room_id, self.uid, self.nickname, self.online_users = 0, 0, '', 0

    async def leave(self):
        async with self._lifecycle:
            if self.state == 'joined':
                with contextlib.suppress(Exception):
                    await self._request(p.LEAVE, p.room_request(self._token), timeout=self._leave_timeout)
            await self._close()
            self.state, self.error = 'disconnected', ''
            self.room_id, self.uid, self.nickname, self.online_users = 0, 0, '', 0
            self._event('status', text='Disconnected.')

    async def send_chat(self, text, *, _session_id=None):
        async with self._lifecycle:
            if _session_id is not None and _session_id != self.session_id:
                raise ValueError('room session changed before queued chat could be sent')
            if self.state != 'joined':
                raise ValueError('room entry has not succeeded')
            await self._request(p.CHAT, p.chat_request(self._token, text, self.nickname))
            return {'accepted': True, 'text': text}

    async def take_seat(self, seat_id):
        async with self._lifecycle:
            if self.state != 'joined':
                raise ValueError('room entry has not succeeded')
            if self._application_id:
                raise ValueError('Cancel the pending seat application before requesting a direct seat.')
            session_id = self.session_id
            try:
                reply = await self._request(p.JOIN_SEAT, p.room_request(self._token) + p.integer(3, seat_id))
                if self.state != 'joined' or self.session_id != session_id or not self._token:
                    raise ValueError(self.error or 'Room session ended before seat confirmation.')
                accepted = p.first(reply, 2, 0)
                if accepted != seat_id:
                    raise ValueError('server did not confirm the requested seat')
            except (ValueError, TimeoutError) as error:
                self.error = str(error) or 'Seat request acknowledgement timed out.'
                self._event('status', text=self.error)
                raise
            self.error = ''
            self.seat_id = accepted
            self._event('status', text='Seat %s acknowledged; audio publication is not enabled.' % accepted)
            return {'seat_id': accepted, 'audio_available': False}

    def _reset_application(self):
        self._application_id = None
        self.seat_application = 'idle'

    async def apply_for_seat(self):
        async with self._lifecycle:
            if self.state != 'joined':
                raise ValueError('room entry has not succeeded')
            if self._application_id or self.seat_id:
                raise ValueError('Already seated or waiting for approval.')
            self._application_id = uuid.uuid4().hex
            self.seat_application = 'applying'
            try:
                await self._request(p.APPLY_SEAT, p.room_request(self._token) + p.blob(3, self.nickname))
            except (ValueError, TimeoutError) as error:
                self._application_id = None
                self.seat_application = 'failed'
                self.error = str(error) or 'Seat application acknowledgement timed out.'
                raise
            if self.seat_application != 'applying' or not self._application_id:
                return self.status()  # Rejection may arrive before the ack.
            self.seat_application = 'pending'
            self.error = ''
            self._event('status', text='Seat application accepted; waiting for host approval.')
            return self.status()

    async def cancel_seat_application(self):
        async with self._lifecycle:
            if self.state != 'joined' or not self._application_id:
                raise ValueError('No pending seat application.')
            # Invalidate queued approval before awaiting cancellation, even if
            # the network acknowledgement fails. Never join after local cancel.
            self._application_id = None
            self.seat_application = 'cancelled'
            await self._request(p.CANCEL_APPLY_SEAT, p.room_request(self._token) + p.blob(3, self.nickname))
            self.error = ''
            self._event('status', text='Seat application cancelled.')
            return self.status()

    def _receive_approval(self, event):
        if (event['room_id'] != self.room_id or event['target_uid'] != self.uid or
                event['sequence'] <= self._approval_cursor):
            return
        self._approval_cursor = event['sequence']
        if not self._application_id or self.seat_application not in ('applying', 'pending'):
            return
        if event['type'] == 3 or event['error_code']:
            self._application_id = None
            self.seat_application = 'rejected'
            self.error = 'Host declined the seat application (code %s).' % event['error_code']
            self._event('status', text=self.error)
        elif event['type'] == 2 and 0 < event['seat_id'] < 2**31:
            if self._approval_task and not self._approval_task.done():
                return
            self._approval_task = asyncio.create_task(self._join_approved_seat(
                self._application_id, self.session_id, event['seat_id']))

    async def _join_approved_seat(self, application_id, session_id, seat_id):
        # The reader must keep running to receive the join acknowledgement.
        async with self._lifecycle:
            if (self.state != 'joined' or self.session_id != session_id or
                    self._application_id != application_id or self.seat_application != 'pending'):
                return
            self.seat_application = 'joining'
            self._event('status', text='Host approved seat %s; waiting for seat acknowledgement.' % seat_id)
            try:
                reply = await self._request(p.JOIN_SEAT, p.room_request(self._token) +
                                            p.integer(3, seat_id) + p.integer(4, 1))
                if (self.state != 'joined' or self.session_id != session_id or
                        self._application_id != application_id or not self._token):
                    raise ValueError('Room session ended before approved seat confirmation.')
                if p.first(reply, 2, 0) != seat_id:
                    raise ValueError('Server did not confirm the approved seat.')
                self.seat_id = seat_id
                self.seat_application = 'seated'
                self.error = ''
                self._event('status', text='Approved seat %s acknowledged; audio is not enabled.' % seat_id)
            except (ValueError, TimeoutError) as error:
                self.seat_application = 'failed'
                self.error = str(error) or 'Approved seat acknowledgement timed out.'
                self._event('status', text=self.error)
            finally:
                self._application_id = None


room_service = RoomService()
