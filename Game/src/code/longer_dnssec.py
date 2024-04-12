import dns.dnssec
from cryptography.hazmat.primitives import serialization
from scapy.layers.dns import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
from cryptography.x509 import *
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.serialization import *

SERVER_NAME = "www.cyberoffensive.com."
SERVER_NAME_PART2 = "cyberoffensive.com"
SERVER_IP = conf.route.route("0.0.0.0")[1]
THE_PEM = serialization.Encoding.DER
PREFER_PADDING = PSS(MGF1(hashes.SHA256()), PSS.MAX_LENGTH)


class ServerSearcher:

    def __init__(self):
        pass

    def run(self):
        """

        """

        full_base = Ether(src=Ether().src, dst=Ether().src) / IP(src=SERVER_IP, dst=SERVER_IP) / UDP(dport=53)
        with open(f'Certificates\\certificate0.pem', 'rb') as certificate_first:
            my_cert_pem = load_pem_x509_certificate(certificate_first.read())

        with open(f'Keys\\the_key0.pem', 'rb') as certificate_first:
            my_key_pem = load_pem_private_key(certificate_first.read(), password=b'gfdgdfgdhffdgfdgfdgdf')

        dns_sec_key = dns.dnssec.make_dnskey(my_cert_pem.public_key(), dns.dnssec.Algorithm.RSASHA1)
        c_dns_sec_key = dns.dnssec.make_cdnskey(my_cert_pem.public_key(), dns.dnssec.Algorithm.RSASHA1)

        del_dns_sec_key = dns.dnssec.make_cdnskey(my_cert_pem.public_key(), dns.dnssec.Algorithm.RSASHA1NSEC3SHA1)
        del_c_dns_sec_key = dns.dnssec.make_cdnskey(my_cert_pem.public_key(), dns.dnssec.Algorithm.RSASHA1NSEC3SHA1)

        digest_del_s_k = del_dns_sec_key.to_digestable()
        digest_del_s_k_c = del_c_dns_sec_key.to_digestable()

        pair_1_sec_key = dns.dnssec.make_dnskey(my_cert_pem.public_key(), dns.dnssec.Algorithm.RSASHA1NSEC3SHA1)
        pair_1_c_dns_sec_key = dns.dnssec.make_cdnskey(my_cert_pem.public_key(), dns.dnssec.Algorithm.RSASHA1NSEC3SHA1)

        pair_2_dns_sec_key = dns.dnssec.make_dnskey(my_cert_pem.public_key(), dns.dnssec.Algorithm.RSASHA1NSEC3SHA1)
        pair_2_c_dns_sec_key = dns.dnssec.make_cdnskey(my_cert_pem.public_key(), dns.dnssec.Algorithm.RSASHA1NSEC3SHA1)

        digest_del2_s_k = pair_2_dns_sec_key.to_digestable()
        digest_del2_s_k_c = pair_2_c_dns_sec_key.to_digestable()

        p_pack = DNS(rd=1, qd=DNSQR(qname=SERVER_NAME, qtype=1))  # Client packet

        rr_record = DNSRR(rrname=SERVER_NAME, rdata=SERVER_IP)

        key_record = DNSRRDNSKEY(rrname=SERVER_NAME[len(SERVER_NAME)-4:len(SERVER_NAME)-1],
                                 publickey=dns_sec_key.key)

        key_c_record = DNSRRDNSKEY(rrname=SERVER_NAME[len(SERVER_NAME)-4:len(SERVER_NAME)-1],
                                   publickey=c_dns_sec_key.key, flags=0x0101)

        delegation_sha_record = DNSRRDS(rrname=SERVER_NAME[4:], digest=digest_del2_s_k)

        delegation_sha_big_record = DNSRRDS(rrname=SERVER_NAME[4:], digest=digest_del2_s_k_c)

        pair_1_key_record = DNSRRDNSKEY(rrname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1],
                                        publickey=pair_1_sec_key.key)

        pair_1_key_c_record = DNSRRDNSKEY(rrname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1],
                                          publickey=pair_1_c_dns_sec_key.key, flags=0x0101)

        pair_2_key_record = DNSRRDNSKEY(rrname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1],
                                        publickey=pair_2_dns_sec_key.key)

        pair_2_key_c_record = DNSRRDNSKEY(rrname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1],
                                          publickey=pair_2_c_dns_sec_key.key, flags=0x0101)

        delegation_sha2_record = DNSRRDS(rrname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1],
                                         digest=digest_del_s_k)

        delegation_sha2_big_record = DNSRRDS(rrname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1],
                                             digest=digest_del_s_k_c)

        signed_rr_record = my_key_pem.sign(bytes(rr_record), PREFER_PADDING, hashes.SHA1())

        signed_key_record = my_key_pem.sign(bytes(key_record), PREFER_PADDING, hashes.SHA1())

        signed_c_key_record = my_key_pem.sign(bytes(key_c_record), PREFER_PADDING, hashes.SHA1())

        signed_delegation_record = my_key_pem.sign(bytes(delegation_sha_record), PREFER_PADDING, hashes.SHA1())

        signed_r_k_record = my_key_pem.sign(bytes(pair_2_key_record), PREFER_PADDING, hashes.SHA1())

        signed_r_k_c_record = my_key_pem.sign(bytes(pair_2_key_c_record), PREFER_PADDING, hashes.SHA1())

        signed_com_delegation_record = my_key_pem.sign(bytes(delegation_sha2_record), PREFER_PADDING, hashes.SHA1())

        # Server packet
        a_pack = DNS(qr=1, ra=1, rd=1, ancount=2, arcount=1, qd=DNSQR(qname=SERVER_NAME), an=rr_record /
                     DNSRRRSIG(rrname=SERVER_NAME, signersname=SERVER_NAME_PART2, signature=signed_rr_record),
                     ar=DNSRROPT())

        key_request = DNS(qr=1, ra=1, rd=1, arcount=1, qd=DNSQR(qname=SERVER_NAME[4:], qtype=48), ar=DNSRROPT())

        key_pack = DNS(qr=1, ra=1, rd=1, ancount=4, arcount=1, qd=DNSQR(qname=SERVER_NAME[4:], qtype=48),
                       an=key_record / key_c_record / DNSRRRSIG(rrname=SERVER_NAME[4:], signersname=SERVER_NAME_PART2,
                       signature=signed_key_record, typecovered=48) /
                       DNSRRRSIG(rrname=SERVER_NAME[4:], signersname=SERVER_NAME_PART2, typecovered=48,
                       signature=signed_c_key_record), ar=DNSRROPT())

        delegation_request = DNS(qr=1, ra=1, rd=1, arcount=1, qd=DNSQR(qname=SERVER_NAME[4:], qtype=43), ar=DNSRROPT())

        delegation_pack = DNS(qr=1, ra=1, rd=1, ancount=3, arcount=1, qd=DNSQR(qname=SERVER_NAME[4:], qtype=43),
                              an=delegation_sha_record / delegation_sha_big_record /
                              DNSRRRSIG(rrname=SERVER_NAME[4:], algorithm=7, typecovered=43,
                                        signersname=SERVER_NAME[len(SERVER_NAME)-4:len(SERVER_NAME)-1],
                                        signature=signed_delegation_record), ar=DNSRROPT())

        root_key_request = DNS(qr=1, ra=1, rd=1, arcount=1,
                               qd=DNSQR(qname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1], qtype=48),
                               ar=DNSRROPT())

        root_key_answers = DNS(qr=1, ra=1, rd=1, ancount=6, arcount=1,
                               qd=DNSQR(qname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1], qtype=48),
                               an=pair_1_key_record / pair_1_key_c_record / pair_2_key_record / pair_2_key_c_record /
                               DNSRRRSIG(rrname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1], algorithm=7,
                                         typecovered=43,
                                         signersname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1],
                                         signature=signed_r_k_record) /
                               DNSRRRSIG(rrname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1], algorithm=7,
                                         typecovered=43,
                                         signersname=SERVER_NAME[len(SERVER_NAME) - 4:len(SERVER_NAME) - 1],
                                         signature=signed_r_k_c_record),
                               ar=DNSRROPT())

        full_pack = (full_base / a_pack)
        full_pack = self.prepare_packet(full_pack)
        sendp(full_pack)

        p_pack = self.prepare_packet(p_pack)
        a_pack = self.prepare_packet(a_pack)

        key_request = self.prepare_packet(key_request)
        key_pack = self.prepare_packet(key_pack)

        delegation_request = self.prepare_packet(delegation_request)
        delegation_pack = self.prepare_packet(delegation_pack)

        root_key_request = self.prepare_packet(root_key_request)
        root_key_answers = self.prepare_packet(root_key_answers)

     #   self.show_packet(p_pack)
       # self.show_packet(a_pack)
    #    self.show_packet(full_pack)
        self.show_packet(key_request)
        self.show_packet(key_pack)

        self.show_packet(delegation_request)
        self.show_packet(delegation_pack)

        self.show_packet(root_key_request)
        self.show_packet(root_key_answers)

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
