from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dh, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hashlib

SYN = 2
FIN = 1
ACK = 16
MAC_ADDRESS = Ether().src
MY_IP = conf.route.route('0.0.0.0')[1]
NETWORK_MAC = getmacbyip(conf.route.route('0.0.0.0')[2])
DONT_FRAGMENT_FLAG = 2
MSS = [("MSS", 1460)]
N = RandShort()  # Key base number
TLS_MID_VERSION = "TLS 1.2"
TLS_NEW_VERSION = "TLS 1.3"
TLS_PORT = 443
RECOMMENDED_CIPHER = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
H_NAME = "bro"
KEY_ENC = serialization.Encoding.X962
FORMAT_PUBLIC = serialization.PublicFormat.UncompressedPoint


def filter_tcp(packets):
    """
     Filter for tcp packets
    :param packets: The packet received
    :return: Whether the packet is a SYN TCP packet
    """

    return (TCP in packets and (packets[TCP].flags == DONT_FRAGMENT_FLAG or packets[TCP].flags == ACK) and
            IP in packets and packets[IP].dst == MY_IP and packets[TCP].dport == TLS_PORT)


def print_flags(packets):
    """
     Print TCP flag
    :param packets: The TCP packet
    """

    print("Packet's flag is\n", packets[TCP].flags)


def create_response(packet_auth):
    """
     Server response
    :param packet_auth: The SYN + ACK packet
    :return packet_auth
    """

    packet_auth[Ether].dst = packet_auth[Ether].src
    packet_auth[Ether].src = MAC_ADDRESS

    packet_auth[IP].flags = DONT_FRAGMENT_FLAG
    packet_auth[TCP].ack = packet_auth[TCP].seq + 1

    packet_auth[TCP].flags = SYN + ACK
    packet_auth[TCP].seq = RandShort()

    new_src = packet_auth[IP].dst
    new_dst = packet_auth[IP].src

    new_sport = packet_auth[TCP].dport
    new_dport = packet_auth[TCP].sport

    packet_auth[IP].src = new_src
    packet_auth[IP].dst = new_dst

    packet_auth[TCP].sport = new_sport
    packet_auth[TCP].dport = new_dport

    packet_auth[TCP].options = MSS
    packet_auth[Raw].load = b"hello"
    packet_auth = packet_auth.__class__(bytes(packet_auth))

    return packet_auth


def filter_tls(packets):
    """
     Filter tcp packets
    :param packets: The packet received
    :return: Whether the packet is a SYN TCP packet
    """

    return TLSClientHello in packets or TLSClientKeyExchange in packets


def create_session_id():
    """
     Create session id
    :return: TLS session id
    """

    s_sid = hashlib.sha256()
    s_sid.update(bytes(N))
    s_sid = s_sid.hexdigest()

    return s_sid


def basic_start_tls(s_p):
    """
     Create a tcp ack packet
    :param s_p: Create a tcp ack packet
    :return: A tcp ack packet
    """

    first_seq = s_p[TCP].seq
    first_ack = s_p[TCP].ack

    return (Ether(src=s_p[Ether].dst, dst=s_p[Ether].src) / IP(dst=s_p[IP].src, flags=DONT_FRAGMENT_FLAG) /
            TCP(flags=ACK, sport=TLS_PORT, dport=RandShort(), seq=first_seq, ack=first_ack))


def new_certificate(basic_tcp):
    """
     Create TLS certificate packet
    :param basic_tcp: Layers 2-4
    :return: The TLS certificate
    """

    original_cert, key = create_x509()
    server_cert = Cert(original_cert)
    server_cert.show()
    print(key, "\n", server_cert.signatureValue)

    cert_tls = ((TLS(msg=TLSCertificate(certs=server_cert)) /
                TLS(msg=TLSServerHelloDone())))
    cert_msg = basic_tcp / cert_tls
    cert_msg.show()
    cert_msg = cert_msg.__class__(bytes(cert_msg))
    cert_msg.show()

    return cert_msg


def create_x509():
    """
     Create The X509 certificate and server key
    :return: The Certificate and server key
    """

    # RSA AND ECDH keys (NOTE: This code currently uses the RSA key only)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(b"data & ")
    hasher.update(b"more data")
    digest = hasher.finalize()
    signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(chosen_hash)))
    serialized_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'sdsdsdsdsd')
    )
    print(serialized_private.splitlines()[0])

    loaded_private_key = serialization.load_pem_private_key(serialized_private, password=b'sdsdsdsdsd')

    # Create the certificate

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, H_NAME)])

    alt_names = [x509.DNSName(H_NAME), x509.DNSName(MY_IP)]

    print(alt_names)

    basic_constraints = x509.BasicConstraints(ca=True, path_length=0)

    now = datetime.utcnow()

    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1000)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(basic_constraints, True)
            .add_extension(x509.SubjectAlternativeName(alt_names), False)
            .sign(key, hashes.SHA256(), default_backend())
            )
    print("===================\n", key.public_key().public_numbers(), "\n==================")
    my_cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    my_key_pem = loaded_private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                  encryption_algorithm=serialization.BestAvailableEncryption(b"djvbjdshbffvdsf"))
    return my_cert_pem, my_key_pem


def new_secure_session(basic_tcp, s_sid):
    """
     Create the server hello packet
    :param basic_tcp: The layers 2-4
    :param s_sid: TLS Session ID
    :return: TLS server hello packet
    """

    security_layer = (TLS(msg=TLSServerHello(sid=s_sid, cipher=RECOMMENDED_CIPHER,
                                             ext=TLS_Ext_SupportedVersion_SH(version=[TLS_MID_VERSION]) /
                                             TLS_Ext_SignatureAlgorithmsCert(sig_algs=["sha256+rsa"]))))

    security_packet = basic_tcp / security_layer
    security_packet.__class__(bytes(security_packet))
    #security_packet.show()

    return security_packet


def create_server_final(basic_tcp):
    """
     Create the server key exchange packet
    :param basic_tcp: Layers 2-4
    :return: The server key exchange packet
    """

    server_key = TLS(msg=TLSChangeCipherSpec())
    server_ex = basic_tcp / server_key
    server_ex = server_ex.__class__(bytes(server_ex))

    return server_ex


def main():
    """
    Main function
    """

    p = sniff(count=1, lfilter=filter_tcp, prn=print_flags)
    p[0].show()
    packet_auth = p[0]
    response = create_response(packet_auth)

    acked = srp1(response)

    tls_p = sniff(count=1, lfilter=filter_tls, prn=print_flags)

    print(tls_p)
    s_p = tls_p[0]
    s_p.show()
    acked.show()

    s_sid = create_session_id()
    basic_tcp = basic_start_tls(s_p)
    certificate = new_certificate(basic_tcp)

    sec_res = new_secure_session(basic_tcp, s_sid)
    sendp([sec_res, certificate])

    tls_k = sniff(count=1, lfilter=filter_tls, prn=print_flags)
    client_key = tls_k[0]
    client_key.show()

    server_final = create_server_final(basic_tcp)
    server_final.show()
    sendp(server_final)

    some_data = basic_tcp / TLS(msg=TLSApplicationData(data=b"jejfnjdfsgbjbhdfs"))
    some_data = some_data.__class__(bytes(some_data))
    some_data.show()
    sendp(some_data)


if __name__ == '__main__':
    main()
