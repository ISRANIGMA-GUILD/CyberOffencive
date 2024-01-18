from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
import hashlib


SYN = 2
FIN = 1
ACK = 16
MAC_ADDRESS = Ether().src
MY_IP = conf.route.route('0.0.0.0')[1]
MSS = [("MSS", 1460)]
N = RandShort()  # Key base number
TLS_MID_VERSION = "TLS 1.2"
TLS_NEW_VERSION = "TLS 1.3"
TLS_PORT = 443
RECOMMENDED_CIPHER = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"


def filter_tcp(packets):
    """
    filter for tcp packets
    :param packets: The packet received
    :return: Whether the packet is a SYN TCP packet
    """

    return (TCP in packets and (packets[TCP].flags == 2 or packets[TCP].flags == ACK) and IP in packets and packets[IP].src == MY_IP
            and packets[IP].dst == MY_IP and packets[TCP].dport == TLS_PORT)


def print_syn(packets):
    """
     print syn
    :param packets: The TCP packet
    """

    print("Packet's syn is\n", packets[TCP].flags)


def create_response(packet_auth):
    """
     server response
    :param packet_auth: The SYN + ACK packet
    :return packet_auth
    """

    packet_auth[IP].flags = 2
    packet_auth[TCP].ack = packet_auth[TCP].seq + 1
    packet_auth[TCP].flags = SYN + ACK
    packet_auth[TCP].seq = RandShort()
    new_src = packet_auth[TCP].dport
    new_dst = packet_auth[TCP].sport

    packet_auth[TCP].sport = new_src
    packet_auth[TCP].dport = new_dst
    packet_auth[TCP].options = MSS
    packet_auth[Raw].load = b"hello"
    packet_auth = packet_auth.__class__(bytes(packet_auth))

    return packet_auth


def filter_tls(packets):
    """
    filter for tcp packets
    :param packets: The packet received
    :return: Whether the packet is a SYN TCP packet
    """

    return TLSClientHello in packets or TLSClientKeyExchange in packets


def print_ack(packets):
    """
     print syn
    :param packets: The TCP packet
    """

    print("Packet's syn is\n", packets[TCP].flags)


def create_session_id():

    s_sid = hashlib.sha256()
    s_sid.update(bytes(N))
    s_sid = s_sid.hexdigest()

    return s_sid


def basic_start_tls(s_p):

    first_seq = s_p[TCP].seq
    first_ack = s_p[TCP].ack

    return (Ether(src=MAC_ADDRESS, dst=MAC_ADDRESS) / IP(src=MY_IP, dst=MY_IP, flags=2) /
                 TCP(flags=ACK, sport=TLS_PORT, dport=RandShort(), seq=first_seq, ack=first_ack))


def new_certificate(basic_tcp):

    original_cert = X509_Cert()
    original_cert = original_cert.__class__(bytes(original_cert))
    original_cert.show()

    server_cert = Cert(original_cert)
    server_cert.show()

    cert_tls = (TLS(msg=TLSCertificate(certs=server_cert)) /
                TLS(msg=TLSServerKeyExchange(params=ServerECDHNamedCurveParams()) / TLSServerHelloDone()))

    cert_msg = basic_tcp / cert_tls

    return cert_msg


def new_secure_session(basic_tcp,  s_sid):

    security_layer = (TLS(msg=TLSServerHello(sid=s_sid, cipher=RECOMMENDED_CIPHER,
                     ext=TLS_Ext_SupportedVersion_SH(version=TLS_MID_VERSION) / TLS_Ext_SignatureAlgorithmsCert())))

    security_packet = basic_tcp / security_layer
    security_packet.__class__(bytes(security_packet))
    security_packet.show()

    return security_packet


def create_server_final(basic_tcp):

    server_key = TLS(msg=TLSChangeCipherSpec()) / TLS(msg=TLSFinished())
    server_ex = basic_tcp / server_key
    server_ex = server_ex.__class__(bytes(server_ex))

    return server_ex


def main():
    """
    Main function
    """

    p = sniff(count=1, lfilter=filter_tcp, prn=print_syn)
    p[0].show()
    packet_auth = p[0]
    response = create_response(packet_auth)

    acked = srp1(response)

    tls_p = sniff(count=1, lfilter=filter_tls, prn=print_ack)

    #tls_p = sniff(count=1, lfilter=filter_tls, prn=print_ack)
    print(tls_p)
    s_p = tls_p[0]
    s_p.show()
    acked.show()

    s_sid = create_session_id()
    basic_tcp = basic_start_tls(s_p)
    certificate = new_certificate(basic_tcp)

    sec_res = new_secure_session(basic_tcp, s_sid)
    sendp([sec_res, certificate])

    tls_k = sniff(count=1, lfilter=filter_tls, prn=print_ack)
    client_key = tls_k[0]
    client_key.show()

    server_final = create_server_final(basic_tcp)
    server_final.show()
    sendp(server_final)


if __name__ == '__main__':
    main()
