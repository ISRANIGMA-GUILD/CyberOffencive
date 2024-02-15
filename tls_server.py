from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import padding
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dh, utils
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
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
TLS_PORT = 989
RECOMMENDED_CIPHER = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
RECOMMENDED_SHA = "sha256+rsa"
H_NAME = "bro"
KEY_ENC = serialization.Encoding.X962
FORMAT_PUBLIC = serialization.PublicFormat.UncompressedPoint
THE_PEM = serialization.Encoding.PEM
PRIVATE_OPENSSL = serialization.PrivateFormat.TraditionalOpenSSL
GOOD_PAD = PKCS1v15()
THE_SECRET_LENGTH = 48


def filter_tcp(packets):
    """
     Filter for tcp packets
    :param packets: The packet received
    :return: Whether the packet is a SYN TCP packet
    """

    return (TCP in packets and (packets[TCP].flags == DONT_FRAGMENT_FLAG or packets[TCP].flags == ACK) and
            IP in packets and packets[IP].dst == MY_IP and packets[IP].src == MY_IP)


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
     Filter for tcp packets
    :param packets: The packet received
    :return: Whether the packet is a SYN TCP packet
    """

    return (TCP in packets and packets[TCP].flags == ACK and IP in packets and packets[IP].src == MY_IP
            and packets[IP].dst == MY_IP and TLS in packets)


def create_session_id():
    """
     Create session id
    :return: TLS session id
    """

    s_sid = hashlib.sha256()
    s_sid.update(bytes(N))
    s_sid = s_sid.hexdigest()

    return s_sid


def basic_start_tls(s_p, ports):
    """
     Create a tcp ack packet
    :param s_p: Create a tcp ack packet
    :return: A tcp ack packet
    """

    first_seq = s_p[TCP].seq
    first_ack = s_p[TCP].ack

    return (Ether(src=s_p[Ether].dst, dst=s_p[Ether].src) / IP(dst=s_p[IP].src, flags=DONT_FRAGMENT_FLAG) /
            TCP(flags=ACK, sport=ports, dport=RandShort(), seq=first_seq, ack=first_ack))


def new_certificate(basic_tcp, client_rand, serv_rand):
    """
     Create TLS certificate packet
    :param client_rand:
    :param serv_rand:
    :param basic_tcp: Layers 2-4
    :return: The TLS certificate
    """

    original_cert, key, enc_key = create_x509(client_rand, serv_rand)
    server_cert = Cert(original_cert)

    server_cert.show()
    print(key, "\n", server_cert.signatureValue)

    cert_tls = ((TLS(msg=TLSCertificate(certs=server_cert)) /
                TLS(msg=TLSServerHelloDone())))
    cert_msg = basic_tcp / cert_tls
    cert_msg.show()
    cert_msg = cert_msg.__class__(bytes(cert_msg))
    cert_msg.show()

    return cert_msg, key, enc_key


def create_x509(client_rand, serv_rand):
    """
     Create The X509 certificate and server key
    :return: The Certificate and server key
    """

    # RSA key

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())

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
    my_cert_pem = cert.public_bytes(encoding=THE_PEM)
    my_key_pem = key.private_bytes(encoding=THE_PEM, format=PRIVATE_OPENSSL,
                                   encryption_algorithm=serialization
                                   .BestAvailableEncryption(b"dj$bjd&hb2f3v@d55920o@21sf"))
    #  Recreate for storage :D

    with open('certifacte.crt', 'wb') as certificate_first:
        certificate_first.write(my_cert_pem)

    with open('certifacte.pem', 'wb') as certificate_first:
        certificate_first.write(my_cert_pem)

    with open('the_key.pem', 'wb') as key_first:
        key_first.write(my_key_pem)

    with open("certifacte.pem", "rb") as cert_file:
        server_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

    the_prf = PRF("SHA256", 0x0303)

    pre_master_secret = generate_pre_master_secret()
    padding_s = GOOD_PAD
    print("THE PRE", pre_master_secret)
    encrypted_pre_master_secret = server_cert.public_key().encrypt(pre_master_secret, padding_s)

    master_secret = the_prf.compute_master_secret(pre_master_secret, client_rand, serv_rand)
    key_man = the_prf.derive_key_block(master_secret, serv_rand, client_rand, THE_SECRET_LENGTH)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'encryption_key', backend=default_backend())

    key_man = hkdf.derive(master_secret)

    return my_cert_pem, key, key_man


def generate_pre_master_secret():
    """
     Create the pre master secret
    :return: the pre master secret
    """
    # Generate 48 random bytes
    random_bytes = os.urandom(48)

    # Ensure first two bytes match TLS version (e.g., TLS 1.2 -> b'\x03\x03')
    tls_version = b'\x03\x03'
    random_bytes = tls_version + random_bytes[2:]

    return random_bytes


def new_secure_session(basic_tcp, s_sid):
    """
     Create the server hello packet
    :param basic_tcp: The layers 2-4
    :param s_sid: TLS Session ID
    :return: TLS server hello packet
    """

    security_layer = (TLS(msg=TLSServerHello(sid=s_sid, cipher=RECOMMENDED_CIPHER,
                                             ext=TLS_Ext_SupportedVersion_SH(version=[TLS_MID_VERSION]) /
                                             TLS_Ext_SignatureAlgorithmsCert(sig_algs=[RECOMMENDED_SHA]))))

    security_packet = basic_tcp / security_layer
    security_packet.__class__(bytes(security_packet))
    security_packet.show()

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


def pad_data(data):
    """
     Pad the data
    :param data: The data
    :return: Padded data
    """

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    return padded_data


def unpad_data(data):
    """
     Unpad the data
    :param data: The data
    :return: Unpadded data
    """

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data


def encrypt_data(data, key):
    """
     Encrypt the data with the encryption key
    :param data: The data
    :param key: The encryption key
    :return: The encrypted data + iv
    """

    backend = default_backend()
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    encryptor = cipher.encryptor()
    padded_data = pad_data(data)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_data


def decrypt_data(encrypted_data, key):
    """
     Decrypt the data sent from the server
    :param encrypted_data: The encrypted data
    :param key: The encryption key
    :return: Decrypted data
    """

    backend = default_backend()
    iv = encrypted_data[:16]  # Extract the IV from the encrypted data

    data = encrypted_data[16:]  # Extract the encrypted data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data


def main():
    """
    Main function
    """

    p = sniff(count=1, lfilter=filter_tcp, prn=print_flags)
    p[0].show()
    packet_auth = p[0]

    ports = packet_auth[TCP].dport
    bind_layers(TCP, TLS, sport=ports)
    bind_layers(TCP, TLS, dport=ports)  # replace with random number

    response = create_response(packet_auth)

    acked = srp1(response)

    tls_p = sniff(count=1, lfilter=filter_tls, prn=print_flags)

    print(tls_p)
    s_p = tls_p[0]
    s_p.show()
    acked.show()
    client_rand = s_p[TLS][TLSClientHello].random_bytes

    s_sid = create_session_id()
    basic_tcp = basic_start_tls(s_p, ports)

    sec_res = new_secure_session(basic_tcp, s_sid)
    rand_serv = sec_res[TLS][TLSServerHello].random_bytes
    certificate, key, enc_key = new_certificate(basic_tcp, client_rand, rand_serv)
    sendp([sec_res, certificate])

    tls_k = sniff(count=1, lfilter=filter_tls, prn=print_flags)
    keys = tls_k[0]
    keys.show()
    client_key = keys[TLS][TLSClientKeyExchange][Raw].load
    decrypt_with_public = key.decrypt(client_key, GOOD_PAD)

    print("Decrypted via server key\n", decrypt_with_public)
    print("Encryption key\n", enc_key)

    message = encrypt_data(b"HEY BABE? HOW YA DOIN", enc_key)
    print(message, "\n", decrypt_data(message, enc_key))

    server_final = create_server_final(basic_tcp)
    server_final.show()
    sendp(server_final)

    some_data = basic_tcp / TLS(msg=TLSApplicationData(data=message))

    some_data = some_data.__class__(bytes(some_data))
    some_data.show()
    sendp(some_data)


if __name__ == '__main__':
    main()