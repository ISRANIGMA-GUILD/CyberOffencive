from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *

SYN = 2
FIN = 1
ACK = 16
MAC_ADDRESS = Ether().src
MY_IP = conf.route.route('0.0.0.0')[1]


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

    res[TCP].seq = new_seq
    res[TCP].ack = new_ack
    res = res.__class__(bytes(res))

    return res


def main():
    """
    Main function
    """

    p = (Ether(src=MAC_ADDRESS, dst=MAC_ADDRESS) / IP(src=MY_IP, dst=MY_IP, flags=2) /
         TCP(flags=SYN, sport=RandShort(), dport=RandShort(), seq=RandShort()) / Raw(b"hi"))

    p = p.__class__(bytes(p))
    p.show()
    sendp(p)

    res = srp1(p)
    res.show()
    acked = create_acknowledge(res)
    sendp(acked)


if __name__ == '__main__':
    main()
