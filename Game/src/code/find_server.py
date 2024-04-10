from cryptography.hazmat.primitives import serialization
from scapy.all import *
from scapy.layers.dns import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
from cryptography.x509 import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVER_NAME = "www.cyberoffensive.com."
SERVER_IP = conf.route.route("0.0.0.0")[1]
THE_PEM = serialization.Encoding.PEM


class ServerSearcher:

    def __init__(self):
        pass

    def run(self):
        """

        """
        full_base = Ether(dst=Ether().src) / IP(src=SERVER_IP, dst=SERVER_IP) / UDP(dport=53)
        with open(f'Certificates\\certificate{1}.pem', 'rb') as certificate_first:
            my_cert_pem = load_pem_x509_certificate(certificate_first.read())

        p_pack = DNS(rd=1, qd=DNSQR(qname=SERVER_NAME, qtype=1))  # Client packet

        # Server packet
        a_pack = DNS(qr=1, ra=1, rd=1, ancount=2, arcount=2, qd=DNSQR(qname=SERVER_NAME),
                     an=DNSRR(rrname=SERVER_NAME, rdata=SERVER_IP) /
                     DNSRRDS(rrname=SERVER_NAME), ar=DNSRRRSIG(rrname=SERVER_NAME) /
                     DNSRRDNSKEY(rrname=SERVER_NAME, publickey=my_cert_pem.public_key().public_bytes(encoding=THE_PEM,
                                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)))

        full_pack = (full_base / a_pack)
        sendp(full_pack)

        p_pack = self.prepare_packet(p_pack)
        a_pack = self.prepare_packet(a_pack)

        self.show_packet(p_pack)
        self.show_packet(a_pack)

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


def main():

    searcher = ServerSearcher()
    searcher.run()


if __name__ == '__main__':
    main()
