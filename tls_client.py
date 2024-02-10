from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *


SYN = 2
FIN = 1
ACK = 16
MY_IP = conf.route.route('0.0.0.0')[1]
NETWORK_MAC = getmacbyip(conf.route.route('0.0.0.0')[2])
TLS_MID_VERSION = "TLS 1.2"
TLS_NEW_VERSION = "TLS 1.3"
DONT_FRAGMENT_FLAG = 2
TLS_PORT = 443
RECOMMENDED_CIPHER = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"


def create_acknowledge(res):
    """
     Client response
    :param res: The ACK packet
    """

    new_dst = res[IP].src
    new_src = res[IP].dst

    new_sport = res[TCP].dport
    new_dport = res[TCP].sport

    new_ack = res[TCP].seq + 1
    new_seq = res[TCP].ack + 1

    res[IP].dst = new_dst
    res[IP].src = new_src

    res[TCP].sport = new_sport
    res[TCP].dport = new_dport

    res[TCP].flags = ACK
    res[IP].flags = DONT_FRAGMENT_FLAG

    res[TCP].seq = new_seq
    res[TCP].ack = new_ack

    res[Raw].load = b"thanks"
    res = res.__class__(bytes(res))

    return res


def basic_start_tls(finish_first_handshake):
    """
     Create a basic TCP ACK packet
    :param finish_first_handshake:
    :return: TCP ACK packet (Layers 2-4)
    """

    first_seq = finish_first_handshake[TCP].seq
    first_ack = finish_first_handshake[TCP].ack

    return (Ether(src=finish_first_handshake[Ether].src, dst=finish_first_handshake[Ether].dst) /
            IP(dst=finish_first_handshake[IP].src, flags=DONT_FRAGMENT_FLAG) /
            TCP(flags=ACK, sport=RandShort(), dport=TLS_PORT, seq=first_seq, ack=first_ack))


def start_security(basic_tcp):
    """
     Create client hello packet
    :param basic_tcp: Layers 2-4
    :return: Client hello packet
    """

    ch_packet = TLS(msg=TLSClientHello(ext=TLS_Ext_SupportedVersion_CH(versions=[TLS_NEW_VERSION, TLS_MID_VERSION])))

    client_hello_packet = basic_tcp / ch_packet
    client_hello_packet = client_hello_packet.__class__(bytes(client_hello_packet))
    client_hello_packet.show()

    return client_hello_packet


def filter_tls(packets):
    """
     Filter for tcp packets
    :param packets: The packet received
    :return: Whether the packet is a SYN TCP packet
    """

    return (TCP in packets and packets[TCP].flags == ACK and IP in packets and packets[IP].src == MY_IP
            and packets[IP].dst == MY_IP and TLS in packets and
            (TLSServerHello in packets or TLSCertificate in packets))


def print_ack(packets):
    """
     Print tcp flag
    :param packets: The TCP packet
    """

    print("Packet's syn is\n", packets[TCP].flags)


def create_client_key(basic_tcp):
    """
     Create client key exchange packet
    :param basic_tcp: Layers 2-4
    :return: TLS client key exchange packet
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    key_exc = (TLS(msg=TLSClientKeyExchange()) / TLS(msg=TLSChangeCipherSpec()))

    client_key = basic_tcp / key_exc

    client_key = client_key.__class__(bytes(client_key))
    client_key.show()

    return client_key


def end_connection(basic_tcp):
    """
     Terminate a tcp connection
    :param basic_tcp: Simple TCP packet with ACK flag
    """
    basic_tcp[TCP].flags = FIN
    ack_end = srp1(basic_tcp)
    ack_end[TCP].flags = ACK

    ack_end[TCP].sport = ack_end[TCP].dport
    ack_end[TCP].dport = TLS_PORT

    ack_end[IP].dst = ack_end[IP].src
    ack_end[IP].src = MY_IP

    sendp(ack_end)


def main():
    """
    Main function
    """

    server_ip = input("Enter the ip of the server\n")

    if server_ip == MY_IP:
        server_mac = get_if_hwaddr(conf.iface)
        layer2 = Ether(src=server_mac, dst=server_mac)

    else:
        server_mac = getmacbyip(server_ip)
        layer2 = Ether(dst=server_mac)

    p = (layer2 / IP(dst=server_ip, flags=DONT_FRAGMENT_FLAG) /
         TCP(flags=SYN, sport=RandShort(), dport=TLS_PORT, seq=RandShort()) / Raw(load=b"hi"))

    p = p.__class__(bytes(p))
    p.show()

    res = srp1(p)
    res.show()

    finish_first_handshake = create_acknowledge(res)
    finish_first_handshake.show()
    sendp(finish_first_handshake)  # TCP handshake ends here

    basic_tcp = basic_start_tls(finish_first_handshake)  # TLS handshake starts here, by creating layer 2-4
    client_hello_packet = start_security(basic_tcp)

    client_hello_packet.show()
    sendp(client_hello_packet)

    j = sniff(count=2, lfilter=filter_tls, prn=print_ack)
    j[1].show()
    m = j[1][TLS][TLSCertificate].certs
    print(m)
    client_key = create_client_key(basic_tcp)
    sendp(client_key)


if __name__ == '__main__':
    main()
