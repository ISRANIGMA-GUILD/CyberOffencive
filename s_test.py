from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *

SERVER_IP = conf.route.route('0.0.0.0')[1]
TLS_EXT_COMPRESS_CERTIFICATE = 27
TLS_EXT_APPLICATION_SETTINGS = 17513
TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP = 18
UNKNOWN = 65037  # What is wireshark talking about?


def main():
    clients_h = (TLS(msg=TLSClientHello(ext=TLS_Ext_SupportedVersion_CH(versions=["TLS 1.3", "TLS 1.2"]))))

    encrypted_client_h = clients_h.__class__(bytes(clients_h))

    #clients_h.show()

    encrypted_client_h.show()

    servers_h = (TLS(msg=TLSServerHello(cipher="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                 ext=TLS_Ext_SupportedVersion_SH(version="TLS 1.3"))) / TLS(msg=TLSCertificate()) /
                 TLS(msg=TLSServerKeyExchange(params=ServerECDHNamedCurveParams())) /
                 TLS(msg=TLS_Ext_SignatureAlgorithmsCert())
                 / TLS(msg=TLSServerHelloDone()))

    servers_h = servers_h.__class__(bytes(servers_h))

    servers_h.show()

    client_key = (TLS(msg=TLSClientKeyExchange()) / TLS(msg=TLSChangeCipherSpec()) / TLS(msg=TLSFinished()))

    client_key = client_key.__class__(bytes(client_key))

    client_key.show()

    server_final = (TLS(msg=TLSChangeCipherSpec()) / TLS(msg=TLSFinished()))

    server_final = server_final.__class__(bytes(server_final))

    server_final.show()


if __name__ == '__main__':
    main()
