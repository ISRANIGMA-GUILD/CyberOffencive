from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
import socket
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import *
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib

SYN = 2
FIN = 1
ACK = 16
MAC_ADDRESS = Ether().src
THE_USUAL_IP = '0.0.0.0'
MY_IP = conf.route.route('0.0.0.0')[1]
NETWORK_MAC = getmacbyip(conf.route.route('0.0.0.0')[2])
DONT_FRAGMENT_FLAG = 2
MSS = [("MSS", 1460)]
N = RandShort()  # Key base number
TLS_MID_VERSION = 0x0303
TLS_NEW_VERSION = 0x0304
RECOMMENDED_CIPHER = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val
RECOMMENDED_SHA = "sha256+rsa"
H_NAME = "bro"
KEY_ENC = serialization.Encoding.X962
FORMAT_PUBLIC = serialization.PublicFormat.UncompressedPoint
THE_PEM = serialization.Encoding.PEM
PRIVATE_OPENSSL = serialization.PrivateFormat.TraditionalOpenSSL
GOOD_PAD = PKCS1v15()
THE_SECRET_LENGTH = 48
MAX_MSG_LENGTH = 1024
THE_SHA_256 = hashes.SHA256()
SECP = 0x0017
SIGNATURE_ALGORITHIM = 0x0401


def first_handshake():
    """

    :return: The ack packet and the server port used the client will use
    """

    p = sniff(count=1, lfilter=filter_tcp, prn=print_flags)
    p[0].show()
    packet_auth = p[0]

    server_port = packet_auth[TCP].dport
    bind_layers(TCP, TLS, sport=server_port)
    bind_layers(TCP, TLS, dport=server_port)  # replace with random number

    response = create_response(packet_auth)
    acked = srp1(response)
    acked.show()

    return acked, server_port


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

    new_src_e = packet_auth[Ether].dst
    new_dst_e = packet_auth[Ether].src

    packet_auth[Ether].dst = new_dst_e
    packet_auth[Ether].src = new_src_e

    packet_auth[IP].flags = DONT_FRAGMENT_FLAG

    new_src = packet_auth[IP].dst
    new_dst = packet_auth[IP].src

    new_sport = packet_auth[TCP].dport
    new_dport = packet_auth[TCP].sport

    packet_auth[IP].src = new_src
    packet_auth[IP].dst = new_dst

    packet_auth[TCP].ack = packet_auth[TCP].seq + 1
    packet_auth[TCP].flags = SYN + ACK
    packet_auth[TCP].seq = RandShort()
    packet_auth[TCP].sport = new_sport
    packet_auth[TCP].dport = new_dport
    packet_auth[TCP].options = MSS

    packet_auth[Raw].load = b"hello"
    packet_auth = packet_auth.__class__(bytes(packet_auth))

    return packet_auth


def create_session_id():
    """
     Create session id
    :return: TLS session id
    """

    s_sid = hashlib.sha256()
    s_sid.update(bytes(N))
    s_sid = s_sid.hexdigest()

    return s_sid


def secure_handshake(client_socket, acked, server_port):
    """

    :param client_socket:
    :param acked:
    :param server_port:
    """

    client_hello = client_socket.recv(MAX_MSG_LENGTH)
    s_p = TLS(client_hello)
    s_p.show()

    s_sid = create_session_id()
    basic_tcp = basic_start_tls(acked, server_port)

    sec_res = new_secure_session(basic_tcp, s_sid)
    sec_res.show()

    certificate, key, enc_key, enc_master_c, server_key_ex = new_certificate(basic_tcp)
    client_socket.send(bytes(sec_res[TLS]))
    client_socket.send(bytes(certificate[TLS]))
    client_socket.send(bytes(server_key_ex[TLS]))

    client_key_exchange = client_socket.recv(MAX_MSG_LENGTH)
    keys = TLS(client_key_exchange)
    keys.show()

    client_key = keys[TLSClientKeyExchange][Raw].load
    decrypt_with_public = key.decrypt(client_key[1:], GOOD_PAD)

    print("Decrypted via server key\n", decrypt_with_public, "\n", client_key)
    print("Encryption key\n", enc_key)

    server_final = create_server_final(basic_tcp)
    server_final.show()

    client_socket.send(bytes(server_final[TLS]))

   # some_data = create_and_encrypt(basic_tcp, enc_key)
   # some_data.show()

   # client_socket.send(bytes(some_data[TLS]))


def basic_start_tls(acked, server_port):
    """
     Create a tcp ack packet
    :param server_port:
    :param acked: Create a tcp ack packet
    :return: A tcp ack packet
    """

    first_seq = acked[TCP].seq
    first_ack = acked[TCP].ack

    return (Ether(src=acked[Ether].dst, dst=acked[Ether].src) / IP(dst=acked[IP].src, flags=DONT_FRAGMENT_FLAG) /
            TCP(flags=ACK, sport=server_port, dport=RandShort(), seq=first_seq, ack=first_ack))


def new_certificate(basic_tcp):
    """
     Create TLS certificate packet
    :param basic_tcp: Layers 2-4
    :return: The TLS certificate
    """

    original_cert, key, enc_key, enc_master_c, shared_secret = create_x509()
    server_cert = Cert(original_cert)

    server_cert.show()
    print(key, "\n", server_cert.signatureValue)
    sig = key.sign(shared_secret, GOOD_PAD, THE_SHA_256)  # RSA SIGNATURE on the shared secret
    ec_params = ServerECDHNamedCurveParams(named_curve=SECP, point=enc_master_c)
    d_sign = scapy.layers.tls.keyexchange._TLSSignature(sig_alg=SIGNATURE_ALGORITHIM, sig_val=sig)

    cert_tls = (TLS(msg=TLSCertificate(certs=server_cert)))

    server_key_ex = (TLS(msg=TLSServerKeyExchange(params=ec_params, sig=d_sign)) /
                     TLS(msg=TLSServerHelloDone()))

    cert_msg = basic_tcp / cert_tls
    ske_msg = basic_tcp / server_key_ex
    cert_msg.show()
    cert_msg = cert_msg.__class__(bytes(cert_msg))
    cert_msg.show()

    return cert_msg, key, enc_key, enc_master_c, ske_msg


def create_x509():
    """
     Create The X509 certificate and server key
    :return: The Certificate and server key
    """

    my_cert_pem, my_key_pem, key = generate_cert()

    private_key, encryption_key, shared_secret, ec_point = generate_masters()

    return my_cert_pem, key, encryption_key, ec_point, shared_secret


def generate_cert():
    # RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # Create the certificate

    names = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, H_NAME)])

    alt_names = [x509.DNSName(H_NAME), x509.DNSName(MY_IP)]

    print(alt_names)

    basic_constraints = x509.BasicConstraints(ca=True, path_length=0)

    now = datetime.utcnow()

    cert = (x509.CertificateBuilder()
            .subject_name(names)
            .issuer_name(names)
            .public_key(key.public_key())
            .serial_number(1000)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(basic_constraints, True)
            .add_extension(x509.SubjectAlternativeName(alt_names), False)
            .sign(key, THE_SHA_256, default_backend(), rsa_padding=GOOD_PAD)
            )

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

    return my_cert_pem, my_key_pem, key


def generate_masters():
    """
    Creates both the encryption key, shared secret, ecdh public key point and the private clients ephemeral key
    :return: All that has been created
    """

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Serialize Alice's public key and send it to Bob
    public_key_point = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    print(len(public_key_point))
    # Compute shared key
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_secret)

    return private_key, derived_key, shared_secret, public_key_point


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
    :return: The change cipher spec packet
    """
    with open("certifacte.pem", "rb") as cert_file:
        server_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

    print(len(server_cert.signature))

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


def create_and_encrypt(basic_tcp, enc_key):
    """

    :param basic_tcp:
    :param enc_key:
    :return:
    """

    message = encrypt_data(b"HEY BABE? HOW YA DOIN", enc_key)
    print(message, "\n", decrypt_data(message, enc_key))

    some_data = basic_tcp / TLS(msg=TLSApplicationData(data=message))
    some_data = some_data.__class__(bytes(some_data))

    return some_data


def main():
    """
    Main function
    """

    acked, server_port = first_handshake()

    the_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    the_server_socket.bind((THE_USUAL_IP, server_port))  # Bind the server IP and Port into a tuple
    the_server_socket.listen()  # Listen to client

    print("Server is up and running")

    connection, client_address = the_server_socket.accept()  # Accept clients request
    print("Client connected")

    client_socket = connection

    secure_handshake(client_socket, acked, server_port)

    client_socket.close()
    the_server_socket.close()


if __name__ == '__main__':
    main()
