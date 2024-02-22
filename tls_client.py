from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SYN = 2
FIN = 1
ACK = 16
MY_IP = conf.route.route('0.0.0.0')[1]
NETWORK_MAC = getmacbyip(conf.route.route('0.0.0.0')[2])
TLS_MID_VERSION = 0x0303
TLS_NEW_VERSION = 0x0304
DONT_FRAGMENT_FLAG = 2
RECOMMENDED_CIPHER = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val
GOOD_PAD = PKCS1v15()
THE_SECRET_LENGTH = 48
MAX_MSG_LENGTH = 1024


def the_pre_handshake(server_ip, server_port):
    """
     Initiate the three-way handshake
    :param server_ip: The servers ip
    :param server_port: The chosen server port
    :return: The ack packet
    """

    p = create_syn(server_ip, server_port)
    p.show()

    res = srp1(p)
    res.show()

    finish_first_handshake = create_acknowledge(res)
    finish_first_handshake.show()
    sendp(finish_first_handshake)  # TCP handshake ends here

    return finish_first_handshake


def create_syn(server_ip, server_port):
    """

    :param server_port: The server port
    :param server_ip: The server ip
    :return: The SYN packet
    """

    if server_ip == MY_IP:
        server_mac = get_if_hwaddr(conf.iface)
        layer2 = Ether(src=server_mac, dst=server_mac)

    else:
        server_mac = getmacbyip(server_ip)
        layer2 = Ether(dst=server_mac)

    p = (layer2 / IP(dst=server_ip, flags=DONT_FRAGMENT_FLAG) /
         TCP(flags=SYN, sport=RandShort(), dport=server_port, seq=RandShort()) / Raw(load=b"hi"))

    p = p.__class__(bytes(p))

    return p


def create_acknowledge(res):
    """
     Client response
    :param res: The ACK packet
    :return: The ACK packet
    """

    new_dst_e = res[Ether].src
    new_src_e = res[Ether].dst

    new_dst = res[IP].src
    new_src = res[IP].dst

    new_sport = res[TCP].dport
    new_dport = res[TCP].sport

    new_ack = res[TCP].seq + 1
    new_seq = res[TCP].ack + 1

    res[Ether].dst = new_dst_e
    res[Ether].src = new_src_e

    res[IP].dst = new_dst
    res[IP].src = new_src
    res[IP].flags = DONT_FRAGMENT_FLAG

    res[TCP].sport = new_sport
    res[TCP].dport = new_dport
    res[TCP].flags = ACK
    res[TCP].seq = new_seq
    res[TCP].ack = new_ack

    res[Raw].load = b"thanks"
    res = res.__class__(bytes(res))

    return res


def secure_handshake(the_client_socket, finish_first_handshake, server_port):
    """

    :param the_client_socket:
    :param finish_first_handshake:
    :param server_port:
    """

    basic_tcp = basic_start_tls(finish_first_handshake, server_port)  # TLS handshake starts here, by creating layer 2-4
    client_hello_packet = start_security(basic_tcp)

    client_hello_packet.show()
    the_client_socket.send(bytes(client_hello_packet[TLS]))

    server_hello = the_client_socket.recv(MAX_MSG_LENGTH)
    cert = the_client_socket.recv(MAX_MSG_LENGTH)
    key = the_client_socket.recv(MAX_MSG_LENGTH)

    msg_s = TLS(server_hello)
    msg_cert = TLS(cert)
    msg_key = TLS(key)

    msg_s.show()
    msg_cert.show()
    msg_key.show()

    with open("certifacte.pem", "rb") as server_cert:
        m = x509.load_pem_x509_certificate(server_cert.read())

    sig_tls = scapy.layers.tls.keyexchange._TLSSignature()
    m.public_key().verify(msg_key[TLS][TLSServerKeyExchange][sig_tls].sig_val, msg_key)

    client_key, encryption_key, cert = create_client_key(basic_tcp)
    the_client_socket.send(bytes(client_key[TLS]))

    server_final = the_client_socket.recv(MAX_MSG_LENGTH)
    msg_s_f = TLS(server_final)
    msg_s_f.show()

    data_pack = TLS(the_client_socket.recv(MAX_MSG_LENGTH))
    data_pack.show()
    data = data_pack[TLS][TLSApplicationData].data
    data_iv = data[:12]
    data_tag = data[len(data)-16:len(data)]
    data_c_t = data[12:len(data)-16]

    print(data_iv, data_c_t, data_tag)
    print("==============", "\n", encryption_key, "\n", "==============")
    print("Will decrypt", data)
    print(decrypt_data(encryption_key, b"gg", data_iv, data_c_t, data_tag))


def basic_start_tls(finish_first_handshake, server_port):
    """
     Create a basic TCP ACK packet
    :param server_port: The server port
    :param finish_first_handshake:
    :return: TCP ACK packet (Layers 2-4)
    """

    first_seq = finish_first_handshake[TCP].seq
    first_ack = finish_first_handshake[TCP].ack

    return (Ether(src=finish_first_handshake[Ether].src, dst=finish_first_handshake[Ether].dst) /
            IP(dst=finish_first_handshake[IP].src, flags=DONT_FRAGMENT_FLAG) /
            TCP(flags=ACK, sport=RandShort(), dport=server_port, seq=first_seq, ack=first_ack))


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


def create_client_key(basic_tcp):
    """
     Create client key exchange packet
    :param basic_tcp: Layers 2-4
    :return: TLS client key exchange packet
    """

    with open("certifacte.pem", "rb") as cert_file:
        server_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

    private_key_2, encryption_key, shared_key_2, public_key_point = generate_main_secret()

    client_parameters = ClientECDiffieHellmanPublic(ecdh_Yc=public_key_point)
    key_exc = (TLS(msg=TLSClientKeyExchange(exchkeys=client_parameters)) / TLS(msg=TLSChangeCipherSpec()))

    client_key = basic_tcp / key_exc

    client_key = client_key.__class__(bytes(client_key))
    client_key.show()

    return client_key, encryption_key, server_cert


def generate_main_secret():
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

    print(len(public_key_point), public_key)
    # Compute shared key
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'encryption key').derive(shared_secret)

    return private_key, derived_key, shared_secret, public_key_point


def end_connection(basic_tcp, server_port):
    """
     Terminate a tcp connection
    :param server_port: Servers port
    :param basic_tcp: Simple TCP packet with ACK flag
    """

    basic_tcp[TCP].flags = FIN
    ack_end = srp1(basic_tcp)
    ack_end[TCP].flags = ACK

    ack_end[TCP].sport = ack_end[TCP].dport
    ack_end[TCP].dport = server_port

    ack_end[IP].dst = ack_end[IP].src
    ack_end[IP].src = MY_IP

    sendp(ack_end)


def encrypt_data(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    print(encryptor.tag)

    return iv, ciphertext, encryptor.tag


def decrypt_data(key, associated_data, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


def main():
    """
    Main function
    """

    server_port = int(RandShort())
    bind_layers(TCP, TLS, sport=server_port)
    bind_layers(TCP, TLS, dport=server_port)

    server_ip = input("Enter the ip of the server\n")
    finish_first_handshake = the_pre_handshake(server_ip, server_port)

    the_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    the_client_socket.connect((server_ip, server_port))

    secure_handshake(the_client_socket, finish_first_handshake, server_port)

    the_client_socket.close()


if __name__ == '__main__':
    main()
