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

SYN = 2
FIN = 1
ACK = 16
MY_IP = conf.route.route('0.0.0.0')[1]
NETWORK_MAC = getmacbyip(conf.route.route('0.0.0.0')[2])
TLS_MID_VERSION = 0x0303
TLS_NEW_VERSION = 0x0304
DONT_FRAGMENT_FLAG = 2
RECOMMENDED_CIPHER = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.val
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


def secure_handshake(the_client_socket, finish_first_handshake, server_port):
    """

    :param the_client_socket:
    :param finish_first_handshake:
    :param server_port:
    """

    basic_tcp = basic_start_tls(finish_first_handshake, server_port)  # TLS handshake starts here, by creating layer 2-4
    client_hello_packet = start_security(basic_tcp)
    rand = client_hello_packet[TLS][TLSClientHello].random_bytes

    client_hello_packet.show()
    the_client_socket.send(bytes(client_hello_packet[TLS]))

    server_hello = the_client_socket.recv(MAX_MSG_LENGTH)
    cert = the_client_socket.recv(MAX_MSG_LENGTH)
    msg_s = TLS(server_hello)
    msg_cert = TLS(cert)

    serv_rand = msg_s[TLS][TLSServerHello].random_bytes
    msg_cert.show()

    client_key, encryption_key, cert = create_client_key(basic_tcp, rand, serv_rand)
    the_client_socket.send(bytes(client_key[TLS]))

    server_final = the_client_socket.recv(MAX_MSG_LENGTH)
    msg_s_f = TLS(server_final)
    msg_s_f.show()

    data_pack = TLS(the_client_socket.recv(MAX_MSG_LENGTH))
    data_pack.show()
    data = data_pack[TLS][TLSApplicationData].data
    print(decrypt_data(data, encryption_key))


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

    the_prf = PRF("SHA256", TLS_MID_VERSION)

    pre_master_secret = generate_pre_master_secret()
    padding_s = GOOD_PAD
    print("THE PRE", pre_master_secret)
    encrypted_pre_master_secret = server_cert.public_key().encrypt(pre_master_secret, padding_s)
    print("THE POST", encrypted_pre_master_secret)

    master_secret = the_prf.compute_master_secret(pre_master_secret, client_rand, serv_rand, hashes.SHA256())
    key_man = the_prf.derive_key_block(master_secret, serv_rand, client_rand, THE_SECRET_LENGTH)
    key_man.hex()

    print("\n=====================", key_man, "\n", key_man.hex(), "\n=====================")
    client_parameters = ClientECDiffieHellmanPublic(ecdh_Yc=encrypted_pre_master_secret)
    key_exc = (TLS(msg=TLSClientKeyExchange(exchkeys=client_parameters)) / TLS(msg=TLSChangeCipherSpec()))

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
