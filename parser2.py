import argparse
from textwrap import indent
from dataclasses import dataclass
from typing import List, BinaryIO, Any
from datetime import datetime, UTC
import binascii
import struct
import sys
import io
import string
import time
import json

def is_printable(i):
    return i >= 0x20 and i < 0x7f

def to_ascii(data):
    return ''.join([ chr(c) if is_printable(int(c)) else '.' for c in data ])

def warn(*a):
    print('[WARN]', *a, file = sys.stderr)

def parse_(fmt, id, data):
    size     = struct.calcsize(fmt)
    trailing = len(data) % size
    if trailing:
        warn(f'{trailing} trailing bytes while parsing {id}')
        data = data[:len(data) - trailing]
    return [ r[0] for r in struct.iter_unpack(fmt, data) ]

parse_U8  = lambda v, *a: parse_('<B', 'U8', v)
parse_U16 = lambda v, *a: parse_('<H', 'U16', v)
parse_U32 = lambda v, *a: parse_('<L', 'U32', v)
parse_I8  = lambda v, *a: parse_('<b', 'I8', v)
parse_I16 = lambda v, *a: parse_('<h', 'I16', v)
parse_I32 = lambda v, *a: parse_('<l', 'I32', v)

def parse_TimeOfDay(v, *a):
    # STRUCT OF
    #   UNSIGNED28 ms,
    #   VOID4      reserved,
    #   UNSIGNED16 days
    EPOCH        = 441763200 # 1984-01-01T00:00:00Z
    millis, days = struct.unpack('<LH', v)
    timestamp    = EPOCH + int(millis / 1000) + days * 24 * 60 * 60
    return (timestamp, datetime.fromtimestamp(timestamp, UTC).isoformat())

def parse_Enum(v, key):
    obj = OBJECTS[key]
    v   = str(parse_U8(v)[0])
    return obj['values'][v]['description'] if v in obj['values'] else v

def parse_VisibleString(v, *a):
    try:
        v = v.decode('ascii')
    except:
        warn('unable to convert bytes to ASCII')
        return v
    # visible strings seem to be NUL-padded
    return v.split('\0', 1)[0]

# https://stackoverflow.com/a/75328573
def crc16modbus(data:str) -> int:
    crc = 0xFFFF
    for n in range(len(data)):
        crc ^= data[n]
        for i in range(8):
            if crc & 1:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc

OBJECTS = json.load(open('object-dictionary.json'))
FORMATS = {
    'U8':            parse_U8,
    'U16':           parse_U16,
    'U32':           parse_U32,
    'I8':            parse_I8,
    'I16':           parse_I16,
    'I32':           parse_I32,
    'TimeOfDay':     parse_TimeOfDay,
    'Enum':          parse_Enum,
    'VisibleString': parse_VisibleString,
}

class DataObject:
    obj:         dict
    msg:         Any
    index:       int
    subindex:    int
    type:        str
    description: str
    value:       Any   = None # can be of multiple types
    unit:        str   = None
    gain:        float = 1.0
    is_array:    bool  = False

    def __str__(self):
        r = (
            f'Index      : {self.index} / {int(self.index, 16)}\n'
            f'Subindex   : {self.subindex}\n'
            f'Type       : {self.type}\n'
            f'Name       : {self.name}\n'
            f'Description: {self.description}'
        )
        if self.msg.is_reply:
            r += f'\nValue      : {self.value}{ " " + self.unit if self.unit else ''}'
        return r

    @staticmethod
    def from_message(msg):
        if msg.index not in OBJECTS:
            warn(f'unknown object (index {msg.index})')
            return None

        obj                 = OBJECTS[msg.index]
        dataobj             = DataObject()
        dataobj.obj         = obj
        dataobj.msg         = msg
        dataobj.index       = msg.index
        dataobj.subindex    = msg.subindex
        dataobj.type        = obj['type']
        dataobj.value       = msg.data
        dataobj.name        = obj['name']
        dataobj.description = obj['desc']

        if msg.is_reply:
            if dataobj.type in FORMATS:
                try:
                    dataobj.value = FORMATS[dataobj.type](dataobj.value, msg.index)
                    if 'gain' in obj:
                        dataobj.gain  = obj['gain']
                        if dataobj.gain != 1.0:
                            dataobj.value = [ v * dataobj.gain for v in dataobj.value ]
                    if obj['is_array']:
                        # validate array size
                        max_allowed = obj.get('max_array_size', 1)
                        if len(dataobj.value) > max_allowed:
                            warn(f'array size larger than allowed (size={len(value)}, max allowed={max_allowed})')
                    elif dataobj.type != 'TimeOfDay':
                        dataobj.value = dataobj.value[0]
                except Exception as e:
                    warn('formatting of data object failed', e)
            if 'unit' in obj:
                dataobj.unit = obj['unit']

        return dataobj

@dataclass(eq = True, frozen = False)
class QueryMessage:
    frame:        bytes
    is_reply:     bool
    flags:        int
    payload_size: int
    unknowns:     bytes
    index:        str
    subindex:     bytes
    data:         bytes
    checksum:     bytes
    crc:          bytes
    payload:      bytes
    object          # instance of DataObject

    def __str__(self):
        return (
            f'Frame       : {self.frame.hex()}\n'
            f'Class       : QUERY\n'
            f'Type        : { "Reply" if self.is_reply else "Request" }\n'
            f'Flags       : 0b{self.flags:08b} / 0x{self.flags:02X}\n'
            f'Payload size: {self.payload_size} byte{ "" if self.payload_size == 1 else ""}\n'
            f'Unknowns    : {self.unknowns.hex()}\n'
            f'Payload     :\n'
            f'    Raw       : {self.payload.hex()}\n'
            f'    Index     : {self.index}\n'
            f'    Subindex  : {self.subindex}\n'
            f'    Data      : {self.data.hex()} / "{ to_ascii(self.data) }"\n'
            f'    Checksum  : {self.checksum.hex()} ({ "invalid, should be " + self.crc.hex() if not self.checksum_valid() else "valid"})\n'
            f'    DataObject: { ("\n" + indent(str(self.object), " " * 8)) if self.object else "UNKNOWN" }\n'
        )

    def checksum_valid(self) -> bool:
        return self.checksum == self.crc

    @staticmethod
    def get_instance(frame, msg_type, flags, payload_size, unknowns, payload):
        try:
            msg = QueryMessage(
                frame        = frame,
                is_reply     = msg_type[0] == 0x01,
                flags        = flags,
                payload_size = payload_size,
                unknowns     = unknowns,
                index        = payload[0:2].hex().upper(),
                subindex     = payload[2],
                data         = payload[3:-2],
                checksum     = payload[-2:],
                crc          = crc16modbus(frame[1:-2]).to_bytes(2),
                payload      = payload
            )
            msg.object = DataObject.from_message(msg)
            return msg
        except Exception as e:
            print(f'\n[INVALID FRAME] {frame.hex()} ({e})', file = sys.stderr)
            return None

@dataclass(eq = True, frozen = True)
class UnknownMessageType1:
    frame:        bytes
    is_reply:     bool
    flags:        int
    payload_size: int
    unknowns:     bytes
    payload:      bytes

    def __str__(self):
        return (
                f'Frame       : {self.frame.hex()}\n'
                f'Class       : UNKNOWN Type 1\n'
                f'Type        : { "Reply" if self.is_reply else "Request" }\n'
                f'Flags       : 0b{self.flags:08b} / 0x{self.flags:02X}\n'
                f'Payload size: {self.payload_size} byte{ "" if self.payload_size == 1 else ""}\n'
                f'Unknowns    : {self.unknowns.hex()}\n'
                f'Payload     : {self.payload.hex()}\n'
        )

    @staticmethod
    def get_instance(frame, msg_type, flags, payload_size, unknowns, payload):
        try:
            return UnknownMessageType1(
                frame        = frame,
                is_reply     = msg_type[0] == 0x01,
                flags        = flags,
                payload_size = payload_size ,
                unknowns     = unknowns,
                payload      = payload
            )
        except Exception as e:
            print(f'\n[INVALID FRAME] {frame.hex()} ({e})', file = sys.stderr)
            return None

@dataclass(eq = True, frozen = True)
class UnknownMessage:
    frame: bytes

    def __str__(self):
        return (
                f'Frame   : {self.frame.hex()}\n'
                f'Class   : UNKNOWN\n'
        )

    @staticmethod
    def get_instance(frame):
        return UnknownMessage(frame = frame)

class MessageParser:
    def __init__(self, file: BinaryIO):
        self.file = file

    def read_bytes(self, count: int) -> bytes:
        data = self.file.read(count)
        if len(data) < count:
            raise EOFError(f"Expected {count} bytes, got {len(data)}")
        return data

    def next_message(self):
        data = bytes()
        while True:
            data += self.read_bytes(1)
            if data[-2:] == b'\x01\x00':
                # extract frame
                header       = data[-2:]
                msg_type     = self.read_bytes(1)
                flags        = self.read_bytes(1)
                payload_size = self.read_bytes(1)

                # Three bytes with unknown function.
                #
                # The last byte might be a unit id (at least for some requests)
                # as they seem to correspond to similar CANopen messages on the
                # service port.

                unknowns     = self.read_bytes(3)
                payload      = self.read_bytes(payload_size[0])

                # raw frame for display purposes
                frame = header + msg_type + flags + payload_size + unknowns + payload

                # pick message class
                message = None
                match flags:
                    case b'\x00':
                        if payload_size[0] < 5:
                            warn(f'payload size < 5 frame={frame.hex()}')
                        else:
                            message = QueryMessage.get_instance(
                                frame,
                                msg_type,
                                flags[0],
                                payload_size[0],
                                unknowns,
                                payload
                            )
                    case b'\xd0':
                        message = UnknownMessageType1.get_instance(
                            frame,
                            msg_type,
                            flags[0],
                            payload_size[0],
                            unknowns,
                            payload
                        )
                    case _:
                        message = UnknownMessage(frame)

                # create message from frame and emit it
                if message:
                    yield message

                # spurious data
                data = data[:-2]
                if len(data):
                    print(f'[SPURIOUS DATA] {data.hex()}', file = sys.stderr)

                # start over
                data = bytes()

    def parse_all(self):
        for msg in self.next_message():
            print(f'{" Message ":*^30}')
            print(msg)

class HexFile(io.TextIOBase):
    def __init__(self, buffer):
        super().__init__()
        self.buffer = buffer

    def read(self, bytes):
        buf = ""
        while len(buf) < 2*bytes:
            byte = self.buffer.read(1)
            if len(byte) == 0:
                # EOF
                return ''
            if byte in string.hexdigits:
                buf += byte

        return binascii.unhexlify(buf)

def hex_string_to_bytes(hex_string: str) -> bytes:
    """Convert a string of hex values to bytes, ignoring whitespace."""
    hex_string = ''.join(hex_string.split("\n\r\t\f :"))
    return binascii.unhexlify(hex_string)

def main():
    parser = argparse.ArgumentParser(description='Parse binary message format')
    parser.add_argument('input', type=argparse.FileType('rb'), default=sys.stdin,
                       nargs='?', help='Input file path (or - for stdin)')
    parser.add_argument('--hex', action='store_true',
                       help='Input contains hex strings instead of binary data')
    args = parser.parse_args()

    try:
        if args.hex:
            file = HexFile(args.input)
        else:
            file = args.input

        parser = MessageParser(file)
        parser.parse_all()
    finally:
        args.input.close()

if __name__ == "__main__":
    main()
