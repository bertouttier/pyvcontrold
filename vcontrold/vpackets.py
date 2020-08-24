# parses vcontrold serial data
import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import *

START_BYTE = 0x41

TYPES = {
    0x00: "request",
    0x01: "response",
    0x03: "error"
}

COMMANDS = {
    0x01: "readdata",
    0x02: "writedata",
    0x07: "functioncall"
}

class VS2Header(Packet):
    name = 'VS2 Header'
    fields_desc = [
        XByteField("startbyte", START_BYTE),
        ByteField("length", None),
        XByteField("checksum", None)
    ]

    @staticmethod
    def compute_checksum(data):
        checksum = 0x00
        for byte in data:
            checksum += byte
            checksum &= 0xFF
        return checksum

    def post_build(self, p, pay):
        # Switch payload and crc
        length = p[1:2] if self.length is not None else struct.pack('B', len(pay))
        checksum = p[-1:]
        p = p[:1] + length + pay
        p += checksum if self.checksum is not None else struct.pack('B', self.compute_checksum(length+pay))
        return p

    def post_dissect(self, s):
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

    def pre_dissect(self, s):
        # Switch payload and checksum
        start_byte = s[:1]
        length_byte = s[1:2]
        length = struct.unpack('B', s[1:2])[0]
        payload, checksum_byte, s = s[2:length+2], s[length+2:length+3], s[length+3:]
        checksum = struct.unpack('B', checksum_byte)[0]
        calc_checksum = self.compute_checksum(length_byte + payload)
        if checksum != calc_checksum:
            raise Scapy_Exception("Wrong checksum: %d != %d" % (checksum, calc_checksum))
        return start_byte + length_byte + checksum_byte + payload + s

class VS2Data(Packet):
    name = 'VS2 Data'
    fields_desc = [
        ByteEnumField("type", 0, TYPES),
        ByteEnumField("command", 0, COMMANDS),
        XShortField("address", 0),
        FieldLenField('data_len', None, length_of='data', fmt='B'),
        XStrLenField('data', '', max_length=10, length_from=lambda pkt: pkt.data_len)
    ]

    def answers(self, other):
        if (other.__class__ == self.__class__) and \
           (other.address == self.address) and \
           (other.type == 0x00 and (self.type == 0x01 or self.type == 0x03)) and \
           (other.data_len == self.data_len):
            return self.payload.answers(other.payload)
        return 0

bind_layers(VS2Header, VS2Data)
