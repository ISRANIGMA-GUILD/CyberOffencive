# scapy.contrib.description = FreeNet
# scapy.contrib.status = loads

from scapy.all import *
from scapy.layers.l2 import *
from scapy.fields import *
from scapy.layers.inet import *


free_net_mes_types = {1: "first", 2: "end", 3: "data"}
encryption_types = {1: "RSA", 2: "ECDH", 3: "DH"}
free_net_types = {1: ""}


class FreeNet(Packet):
    name = "FreeNet"
    fields_desc = [IntEnumField("type", 1, free_net_mes_types),
                   ShortField("length", None),
                   PacketListField("msg", None)]

    def get_full(self):
        # Required for DNSCompressedPacket
        if isinstance(self.underlayer, TCP):
            return self.original[2:]
        else:
            return self.original

    def post_build(self, pkt, pay):
        if isinstance(self.underlayer, TCP) and self.length is None:
            pkt = struct.pack("!H", len(pkt) - 2) + pkt[2:]
        return pkt + pay

    def pre_dissect(self, s):
        """
        Check that a valid DNS over TCP message can be decoded
        """
        if isinstance(self.underlayer, TCP):

            # Compute the length of the DNS packet
            if len(s) >= 2:
                fnet_len = struct.unpack("!H", s[:2])[0]
            else:
                message = "Malformed DNS message: too small!"
                log_runtime.info(message)
                raise Scapy_Exception(message)

            # Check if the length is valid
            if fnet_len < 3 or len(s) < fnet_len:
                message = "Malformed DNS message: invalid length!"
                log_runtime.info(message)
                raise Scapy_Exception(message)

        return s


class TopSecret(Packet):
    name = "TopSecret"
    fields_desc = [StrField("data", "")]


class PskKeyC(Packet):
    name = "Pre Shared Client Key"
    fields_desc = [IntEnumField("type", 1, {1: "ee"})]


bind_bottom_up(TCP, FreeNet, sport=443, flags=16)
bind_bottom_up(TCP, FreeNet, dport=443, flags=16)
bind_layers(TCP, FreeNet, sport=443, dport=443, flags=16)