from cryptography.hazmat.primitives import serialization
from scapy.all import *
from scapy.layers.dns import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
from cryptography.hazmat.primitives.asymmetric.padding import *

SERVER_NAME = "mad.cyberoffensive.org."
SERVER_NAME_PART2 = "cyberoffensive.org"
SERVER_IP = conf.route.route("0.0.0.0")[1]
ISP_IP = conf.route.route("0.0.0.0")[2]
THE_PEM = serialization.Encoding.DER
PREFER_PADDING = PSS(MGF1(hashes.SHA256()), PSS.MAX_LENGTH)


class ServerSearcher:

    def __init__(self):
        pass

    def run(self):
        """

        """

        full_base = Ether(src=Ether().src, dst=getmacbyip(ISP_IP)) / IP(src=SERVER_IP, dst=ISP_IP) / UDP(dport=53)
        p_pack = DNS(rd=1, qd=DNSQR(qname=SERVER_NAME, qtype=1))  # Client packet

        full_pack = (full_base / p_pack)
        full_pack = self.prepare_packet(full_pack)

        pack = self.contact_domain(full_pack)

        return pack[IP].src

    def prepare_packet(self, the_packet):
        """

        :param the_packet:
        :return:
        """

        return the_packet.__class__(bytes(the_packet))

    def show_packet(self, the_packet):
        """

        :param the_packet:
        """

        the_packet.show()

    def filter_dns_sec(self, packets):
        """

        :param packets:
        :return:
        """

        return DNS in packets and DNSQR in packets and DNSRRRSIG in packets

    def contact_domain(self, full_pack):
        """

        :param full_pack:
        """

        while True:
            try:
                sendp(full_pack)
                pack = sniff(count=1, lfilter=self.filter_dns_sec, timeout=2)
                if not pack:
                    pass

                else:
                    self.show_packet(pack)
                    return pack[0]

            except KeyboardInterrupt:
                break


def main():

    searcher = ServerSearcher()
    searcher.run()


if __name__ == '__main__':
    main()