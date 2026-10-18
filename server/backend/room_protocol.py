"""Gateway codec verified against the local room capture. No network side effects."""
import struct
import zlib
from dataclasses import dataclass

MAGIC = 0x57A73A13
MAX_FRAME = 4 * 1024 * 1024
LOGIN, GATEWAY_PING = 0x01000102, 0x01000101
JOIN, LEAVE, HEARTBEAT, CHAT = 0x02000101, 0x02000102, 0x02000103, 0x02000109
JOIN_SEAT, GET_SEATS = 0x02000301, 0x02000303
APPLY_SEAT, CANCEL_APPLY_SEAT = 0x0200031B, 0x0200031C


def varint(value):
    if not 0 <= value < 1 << 64:
        raise ValueError('unsigned 64-bit value required')
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def integer(number, value):
    return varint(number << 3) + varint(value)


def blob(number, value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    return varint((number << 3) | 2) + varint(len(value)) + value


def read_varint(data, pos):
    value = 0
    for index in range(10):
        if pos >= len(data):
            raise ValueError('truncated varint')
        byte = data[pos]
        pos += 1
        if index == 9 and byte > 1:
            raise ValueError('varint overflow')
        value |= (byte & 127) << (index * 7)
        if not byte & 128:
            return value, pos
    raise ValueError('varint overflow')


def fields(data):
    result, pos = {}, 0
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if not number:
            raise ValueError('invalid protobuf field')
        if wire == 0:
            value, pos = read_varint(data, pos)
        elif wire == 2:
            length, pos = read_varint(data, pos)
            if length > len(data) - pos:
                raise ValueError('truncated protobuf field')
            value, pos = data[pos:pos + length], pos + length
        elif wire in (1, 5):
            length = 8 if wire == 1 else 4
            if length > len(data) - pos:
                raise ValueError('truncated fixed-width field')
            value, pos = data[pos:pos + length], pos + length
        else:
            raise ValueError('unsupported protobuf wire type')
        result.setdefault(number, []).append(value)
    return result


def first(values, number, default=None):
    return values.get(number, [default])[0]


@dataclass(frozen=True)
class Frame:
    kind: int
    uid: int
    opcode: int
    sequence: int | None
    status: int
    payload: bytes


def encode_frame(uid, opcode, payload, sequence=0, kind=1, status=0):
    if kind not in (1, 2, 3):
        raise ValueError('invalid packet type')
    envelope = struct.pack('>III', 0, 0, len(payload)) + payload
    body = struct.pack('>QI', uid, opcode)
    if kind != 3:
        body += struct.pack('>I', sequence)
    if kind == 2:
        body += struct.pack('>I', status)
    body += struct.pack('>I', len(envelope)) + envelope
    checksum = struct.pack('>I', zlib.adler32(body) & 0xFFFFFFFF)
    if len(body) + 16 > MAX_FRAME:
        raise ValueError('frame too large')
    return struct.pack('>III', MAGIC, kind, len(body) + 4) + body + checksum


def decode_frame(data):
    if len(data) < 12:
        raise ValueError('truncated header')
    magic, kind, length = struct.unpack_from('>III', data)
    if magic != MAGIC or kind not in (1, 2, 3):
        raise ValueError('invalid gateway header')
    start = {1: 32, 2: 36, 3: 28}[kind]
    if length + 12 != len(data) or not start + 16 <= len(data) <= MAX_FRAME:
        raise ValueError('invalid gateway length')
    if zlib.adler32(data[12:-4]) & 0xFFFFFFFF != struct.unpack_from('>I', data, len(data) - 4)[0]:
        raise ValueError('gateway checksum mismatch')
    extent = struct.unpack_from('>I', data, start - 4)[0]
    reserved, compression, payload_size = struct.unpack_from('>III', data, start)
    payload = data[start + 12:-4]
    if extent != len(data) - start - 4 or payload_size != len(payload) or reserved != 0:
        raise ValueError('invalid gateway envelope')
    if compression == 1:
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        payload = inflater.decompress(payload, MAX_FRAME + 1)
        if len(payload) > MAX_FRAME or not inflater.eof or inflater.unused_data:
            raise ValueError('invalid or oversized gzip payload')
    elif compression != 0:
        raise ValueError('unsupported gateway compression')
    uid, opcode = struct.unpack_from('>QI', data, 12)
    return Frame(kind, uid, opcode,
                 struct.unpack_from('>I', data, 24)[0] if kind != 3 else None,
                 struct.unpack_from('>I', data, 28)[0] if kind == 2 else 0, payload)


def response_fields(frame):
    if frame.kind != 2 or frame.status != 0:
        raise ValueError('gateway rejected request')
    values = fields(frame.payload)
    base = fields(first(values, 1, b''))
    ret = first(base, 1, 0)
    if ret != 0:
        # Do not include arbitrary server payloads/credentials in application logs.
        raise ValueError('room request rejected (return code %s)' % ret)
    return values


def room_request(token):
    if not token:
        raise ValueError('room token is missing')
    return blob(1, b'') + blob(2, token)


def chat_request(token, text, nickname):
    message = blob(2, blob(1, text))  # Message.CHAT=0, nested ChatMessage.text
    return room_request(token) + blob(4, message) + blob(5, nickname)


def chat_event(payload):
    command = fields(payload)
    message = fields(first(command, 4, b''))
    if first(message, 1, 0) != 0:
        return None
    content = fields(first(message, 2, b''))
    return {'room_id': first(command, 2, 0), 'uid': str(first(command, 3, 0)),
            'nickname': first(command, 5, b'').decode('utf-8', errors='replace'),
            'text': first(content, 1, b'').decode('utf-8', errors='replace'),
            'message_id': first(content, 4, 0)}


def approval_event(payload):
    command = fields(payload)
    message = fields(first(command, 4, b''))
    if first(message, 1, 0) != 14:
        return None
    content = fields(first(message, 2, b''))
    target = fields(first(content, 2, b''))
    return {'room_id': first(command, 2, 0), 'target_uid': first(target, 1, 0),
            'type': first(content, 1, 0), 'seat_id': first(content, 4, 0),
            'error_code': first(content, 7, 0), 'sequence': first(content, 8, 0)}
