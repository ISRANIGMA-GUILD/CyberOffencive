from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *

SYN = 2
FIN = 1
ACK = 16
MAC_ADDRESS = Ether().src
MY_IP = conf.route.route('0.0.0.0')[1]
MSS = [("MSS", 1460)]


def filter_tcp(packets):
    """
    filter for tcp packets
    :param packets: The packet received
    :return: Whether the packet is a SYN TCP packet
    """

    return (TCP in packets and packets[TCP].flags == 2 and packets[IP].src == MY_IP
            and packets[IP].dst == MY_IP)


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
    packet_auth[Raw].padding = b'hello'
    packet_auth = packet_auth.__class__(bytes(packet_auth))

    return packet_auth


def main():
    """
    Main function
    """

    p = sniff(count=1, lfilter=filter_tcp, prn=print_syn)
    p[0].show()
    packet_auth = p[0]
    response = create_response(packet_auth)

    sendp(response)
    acked = srp1(response)
    acked.show()


if __name__ == '__main__':
    main()
