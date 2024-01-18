from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *

SYN = 2
FIN = 1
ACK = 16
MAC_ADDRESS = Ether().src
MY_IP = conf.route.route('0.0.0.0')[1]
TLS_MID_VERSION = "TLS 1.2"
TLS_NEW_VERSION = "TLS 1.3"
TLS_PORT = 443
RECOMMENDED_CIPHER = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"


def create_acknowledge(res):
    """
     client response
    :param res: The ACK packet
    """

    new_src = res[TCP].dport
    new_dst = res[TCP].sport

    new_ack = res[TCP].seq + 1
    new_seq = res[TCP].ack + 1

    res[TCP].sport = new_src
    res[TCP].dport = new_dst
    res[TCP].flags = ACK
    res[IP].flags = 2
    res[TCP].seq = new_seq
    res[TCP].ack = new_ack
    res[Raw].load = b"thanks"
    res = res.__class__(bytes(res))

    return res


def basic_start_tls(finish_first_handshake):
    """

    :param finish_first_handshake:
    :return:
    """
    first_seq = finish_first_handshake[TCP].seq
    first_ack = finish_first_handshake[TCP].ack

    return (Ether(src=MAC_ADDRESS, dst=MAC_ADDRESS) / IP(src=MY_IP, dst=MY_IP, flags=2) /
            TCP(flags=ACK, sport=RandShort(), dport=TLS_PORT, seq=first_seq, ack=first_ack))


def start_security(basic_tcp):
    """

    :param basic_tcp:
    :return:
    """
    security_layer = TLS(msg=TLSClientHello(ext=TLS_Ext_SupportedVersion_CH(
                        versions=[TLS_NEW_VERSION, TLS_MID_VERSION])))

    security_packet = basic_tcp / security_layer
    security_packet = security_packet.__class__(bytes(security_packet))
    security_packet.show()

    return security_packet


def filter_tls(packets):
    """
    filter for tcp packets
    :param packets: The packet received
    :return: Whether the packet is a SYN TCP packet
    """

    return (TCP in packets and packets[TCP].flags == ACK and IP in packets and packets[IP].src == MY_IP
            and packets[IP].dst == MY_IP and TLS in packets and
            (TLSServerHello in packets or TLSCertificate in packets))


def print_ack(packets):
    """
     print syn
    :param packets: The TCP packet
    """

    print("Packet's syn is\n", packets[TCP].flags)


def create_client_key(basic_tcp):

    key_exc = TLS(msg=TLSClientKeyExchange()) / TLS(msg=TLSChangeCipherSpec()) / TLS(msg=TLSFinished())

    client_key = basic_tcp / key_exc
    client_key = client_key.__class__(bytes(client_key))
    client_key.show()

    return client_key


def main():
    """
    Main function
    """

    p = (Ether(src=MAC_ADDRESS, dst=MAC_ADDRESS) / IP(src=MY_IP, dst=MY_IP, flags=2) /
         TCP(flags=SYN, sport=RandShort(), dport=TLS_PORT, seq=RandShort()) / Raw(load=b"hi"))

    p = p.__class__(bytes(p))
    p.show()

    res = srp1(p)
    res.show()

    finish_first_handshake = create_acknowledge(res)
    sendp(finish_first_handshake)
    basic_tcp = basic_start_tls(finish_first_handshake)
    security_packet = start_security(basic_tcp)

    finish_first_handshake.show()
    sendp(security_packet)

    j = sniff(count=2, lfilter=filter_tls, prn=print_ack)
    j[1].show()

    client_key = create_client_key(basic_tcp)
    sendp(client_key)


if __name__ == '__main__':
    main()
