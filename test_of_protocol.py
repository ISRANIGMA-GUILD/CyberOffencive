from scapy.all import *
from scapy.layers.inet import *
from free import *


MY_IP = conf.route.route("0.0.0.0")[1]


def filter_free(packets):

    return FreeNet in packets


j = TCP(seq=1, sport=RandShort(), dport=443)
j.show()
hexdump(j)
p = (Ether(src=Ether().src, dst=Ether().src) /
     IP(src=MY_IP, dst=MY_IP) /
     j / FreeNet(type=1, msg=TopSecret(data="aaaa")))
p = p.__class__(bytes(p))
p.show()
hexdump(p)

sendp(p)
p = sniff(count=1, lfilter=filter_free)
p[0].show()
hexdump(p[0])