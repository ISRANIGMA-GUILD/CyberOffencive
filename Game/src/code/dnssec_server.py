from scapy.all import *
from scapy.layers.dns import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
from cryptography.x509 import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.serialization import *

SERVER_NAME = "mad.cyberoffensive.org."
SERVER_NAME_PART2 = "cyberoffensive.org"
SERVER_IP = conf.route.route("0.0.0.0")[1]
ISP_IP = conf.route.route("0.0.0.0")[2]
THE_PEM = serialization.Encoding.DER
PREFER_PADDING = PSS(MGF1(hashes.SHA256()), PSS.MAX_LENGTH)


class DomainProvider:

    def __init__(self, my_cert_pem, my_key_pem):
        self.__certificate = my_cert_pem
        self.__key = my_key_pem

    def run(self):
        """

        """

        full_base_k = self.create_full_pack()
        a_pack = self.create_record_and_signature()

        full_pack_c = (full_base_k / a_pack)
        full_pack_c = self.prepare_packet(full_pack_c)

        self.handle_client(full_pack_c)

    def create_full_pack(self):
        """

        :return:
        """

        return (Ether(src=Ether().src, dst=getmacbyip(ISP_IP)) / IP(src=SERVER_IP, dst=ISP_IP) /
                UDP(sport=53, dport=53))

    def create_record_and_signature(self):
        """

        """

        rr_record = DNSRR(rrname=SERVER_NAME, rdata=SERVER_IP, ttl=64, rdlen=4)
        signed_rr_record = self.__key.sign(bytes(rr_record), PREFER_PADDING, hashes.SHA1())

        # Server packet
        a_pack = DNS(qr=1, ra=1, rd=1, ad=1, ancount=2, arcount=1, qd=DNSQR(qname=SERVER_NAME), an=rr_record /
                     DNSRRRSIG(rrname=SERVER_NAME, signersname=SERVER_NAME_PART2, signature=signed_rr_record),
                     ar=DNSRROPT())
        a_pack = self.prepare_packet(a_pack)

        return a_pack

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

        return DNS in packets and DNSQR in packets and DNSRR not in packets and DNSRRRSIG not in packets

    def handle_client(self, full_pack_c):
        """

        :param full_pack_c:
        """

        pack = sniff(count=1, lfilter=self.filter_dns_sec)
        pack.show()

        full_pack_c = self.prepare_packet(full_pack_c)
        full_pack_c[IP].dst = pack[0][IP].src

        while True:
            try:
                sendp(full_pack_c, count=2)
                time.sleep(2)

            except KeyboardInterrupt:
                break


def get_certs():
    """

    :return:
    """

    with open(f'Certificates\\certificate0.pem', 'rb') as certificate_first:
        my_cert_pem = load_pem_x509_certificate(certificate_first.read())

    with open(f'Keys\\the_key0.pem', 'rb') as certificate_first:
        my_key_pem = load_pem_private_key(certificate_first.read(), password=b'gfdgdfgdhffdgfdgfdgdf')

    return my_cert_pem, my_key_pem


def main():

    my_cert_pem, my_key_pem = get_certs()
    searcher = DomainProvider(my_cert_pem, my_key_pem)
    searcher.run()


if __name__ == '__main__':
    main()
