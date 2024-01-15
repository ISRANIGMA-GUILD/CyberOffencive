import hashlib
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
from scapy.all import *

SERVER_IP = conf.route.route('0.0.0.0')[1]
N = 3  # Server


def main():

    s_sid = hashlib.sha256()
    s_sid.update(bytes(N))

    original_cert = X509_Cert()
    original_cert = original_cert.__class__(bytes(original_cert))
    original_cert.show()

    server_cert = Cert(original_cert)
    server_cert.show()

    print(s_sid.hexdigest())

    clients_h = (Ether(src=Ether().src, dst=Ether().src) / IP(dst=SERVER_IP) / TCP(flags=16, sport=RandShort()) /
                 TLS(msg=TLSClientHello(ext=TLS_Ext_SupportedVersion_CH(versions=["TLS 1.3", "TLS 1.2"]))))
    encrypted_client_h = clients_h.__class__(bytes(clients_h))

    encrypted_client_h.show()
    sendp(encrypted_client_h)

    servers_h = (Ether(src=Ether().src, dst=Ether().src) / IP(dst=SERVER_IP) /
                 TCP(flags=16, sport=443, dport=clients_h[TCP].sport) /
                 TLS(msg=TLSServerHello(sid=s_sid.hexdigest(), cipher="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                 ext=TLS_Ext_SupportedVersion_SH(version="TLS 1.2") / TLS_Ext_SignatureAlgorithmsCert())) /
                 TLS(msg=TLSCertificate(certs=server_cert)) /
                 TLS(msg=TLSServerKeyExchange(params=ServerECDHNamedCurveParams()) / TLSServerHelloDone()))

    servers_h = servers_h.__class__(bytes(servers_h))

    servers_h.show()

    sendp(servers_h)

    client_key = (Ether(src=Ether().src, dst=Ether().src) / IP(dst=SERVER_IP) /
                  TCP(flags=16, sport=clients_h[TCP].sport)
                  / TLS(msg=TLSClientKeyExchange()) / TLS(msg=TLSChangeCipherSpec()) / TLS(msg=TLSFinished()))

    client_key = client_key.__class__(bytes(client_key))

    client_key.show()

    sendp(client_key)

    server_final = (Ether(src=Ether().src, dst=Ether().src) / IP(dst=SERVER_IP) /
                    TCP(flags=16, sport=443, dport=clients_h[TCP].sport)
                    / TLS(msg=TLSChangeCipherSpec()) / TLS(msg=TLSFinished()))

    server_final = server_final.__class__(bytes(server_final))

    server_final.show()

    sendp(server_final)


if __name__ == '__main__':
    main()
