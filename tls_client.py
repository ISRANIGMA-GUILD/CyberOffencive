from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.asymmetric import rsa, dh, utils
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hashlib

SYN = 2
FIN = 1
ACK = 16
MY_IP = conf.route.route('0.0.0.0')[1]
NETWORK_MAC = getmacbyip(conf.route.route('0.0.0.0')[2])
TLS_MID_VERSION = "TLS 1.2"
TLS_NEW_VERSION = "TLS 1.3"
DONT_FRAGMENT_FLAG = 2
TLS_PORT = 989
RECOMMENDED_CIPHER = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
GOOD_PAD = PKCS1v15()
THE_SECRET_LENGTH = 48


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


def basic_start_tls(finish_first_handshake, ports):
    """
     Create a basic TCP ACK packet
    :param ports:
    :param finish_first_handshake:
    :return: TCP ACK packet (Layers 2-4)
    """

    first_seq = finish_first_handshake[TCP].seq
    first_ack = finish_first_handshake[TCP].ack

    return (Ether(src=finish_first_handshake[Ether].src, dst=finish_first_handshake[Ether].dst) /
            IP(dst=finish_first_handshake[IP].src, flags=DONT_FRAGMENT_FLAG) /
            TCP(flags=ACK, sport=RandShort(), dport=ports, seq=first_seq, ack=first_ack))


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
            and packets[IP].dst == MY_IP and TLS in packets)


def print_ack(packets):
    """
     Print tcp flag
    :param packets: The TCP packet
    """

    print("Packet's syn is\n", packets[TCP].flags)


def create_client_key(basic_tcp, client_rand, serv_rand):
    """
     Create client key exchange packet
    :param basic_tcp: Layers 2-4
    :param client_rand: client nonce
    :param serv_rand: server nonce
    :return: TLS client key exchange packet

    """

    with open("certifacte.pem", "rb") as cert_file:
        server_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

    the_prf = PRF("SHA256", 0x0303)

    pre_master_secret = generate_pre_master_secret()
    padding_s = GOOD_PAD
    print("THE PRE", pre_master_secret)
    encrypted_pre_master_secret = server_cert.public_key().encrypt(pre_master_secret, padding_s)

    master_secret = the_prf.compute_master_secret(pre_master_secret, client_rand, serv_rand)
    key_man = the_prf.derive_key_block(master_secret, serv_rand, client_rand, THE_SECRET_LENGTH)
    key_man.hex()
    print("\n=====================", key_man, "\n", key_man.hex(), "\n=====================")

    key_exc = (TLS(msg=TLSClientKeyExchange(exchkeys=encrypted_pre_master_secret)) /
               TLS(msg=TLSChangeCipherSpec()))

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'encryption_key', backend=default_backend())

    key_man = hkdf.derive(master_secret)
    client_key = basic_tcp / key_exc

    client_key = client_key.__class__(bytes(client_key))
    client_key.show()

    return client_key, key_man, server_cert


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


def main(ports):
    """
    Main function
    """
    bind_layers(TCP, TLS, sport=ports)
    bind_layers(TCP, TLS, dport=ports)  # replace with random number
    server_ip = input("Enter the ip of the server\n")

    if server_ip == MY_IP:
        server_mac = get_if_hwaddr(conf.iface)
        layer2 = Ether(src=server_mac, dst=server_mac)

    else:
        server_mac = getmacbyip(server_ip)
        layer2 = Ether(dst=server_mac)

    p = (layer2 / IP(dst=server_ip, flags=DONT_FRAGMENT_FLAG) /
         TCP(flags=SYN, sport=RandShort(), dport=ports, seq=RandShort()) / Raw(load=b"hi"))

    p = p.__class__(bytes(p))
    p.show()

    res = srp1(p)
    res.show()

    finish_first_handshake = create_acknowledge(res)
    finish_first_handshake.show()
    sendp(finish_first_handshake)  # TCP handshake ends here

    basic_tcp = basic_start_tls(finish_first_handshake, ports)  # TLS handshake starts here, by creating layer 2-4
    client_hello_packet = start_security(basic_tcp)
    rand = client_hello_packet[TLS][TLSClientHello].random_bytes

    client_hello_packet.show()
    sendp(client_hello_packet)

    server_first_responses = sniff(count=2, lfilter=filter_tls, prn=print_ack)
    serv_rand = server_first_responses[0][TLS][TLSServerHello].random_bytes
    server_first_responses[1].show()

    client_key, encryption_key, cert = create_client_key(basic_tcp, rand, serv_rand)
    sendp(client_key)

    data_pack = sniff(count=2, lfilter=filter_tls, prn=print_ack)
 #   data = data_pack[1][TLS][TLSApplicationData].data
   # print(decrypt_data(data, encryption_key))


if __name__ == '__main__':
    ports = int(RandShort())
    bind_layers(TCP, TLS, sport=ports)
    bind_layers(TCP, TLS, dport=ports)
    main(ports)