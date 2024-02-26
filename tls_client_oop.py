from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

SYN = 2
FIN = 1
ACK = 16
MY_IP = conf.route.route('0.0.0.0')[1]
TLS_M_VERSION = 0x0303
TLS_N_VERSION = 0x0304
RECOMMENDED_CIPHER = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val
GOOD_PAD = PKCS1v15()
THE_SECRET_LENGTH = 48
MAX_MSG_LENGTH = 1024
THE_SHA_256 = hashes.SHA256()


class Client:

    def __init__(self):
        pass

    def first_contact(self, server_ip, server_port):
        """

        :param server_ip:
        :param server_port:
        :return:
        """

        if server_ip == MY_IP:
            server_mac = get_if_hwaddr(conf.iface)
            layer2 = Ether(src=server_mac, dst=server_mac)

        else:
            server_mac = getmacbyip(server_ip)
            layer2 = Ether(dst=server_mac)

        udp_packet = (layer2 / IP(src=MY_IP, dst=server_ip) /
                      UDP(sport=RandShort(), dport=server_port) /
                      Raw(load=b'Logged'))

        udp_packet = udp_packet.__class__(bytes(udp_packet))
        udp_packet.show()
        sendp(udp_packet)

        vert = sniff(count=1, lfilter=self.filter_udp, timeout=2)
        vert.show()

    def filter_udp(self, packets):

        return UDP in packets and Raw in packets and packets[Raw].load == b'Accepted'

    def the_pre_handshake(self, server_port, the_client_socket):
        """
         Initiate the three-way handshake
        :param server_port: The chosen server port
        :param the_client_socket:
        :return: The ack packet
        """

        syn_packet = self.create_syn(server_port)
        syn_packet.show()

        the_client_socket.send(bytes(syn_packet[TCP]))
        the_client_socket.send(bytes(syn_packet[Raw]))

        server_response = the_client_socket.recv(MAX_MSG_LENGTH)
        server_message = the_client_socket.recv(MAX_MSG_LENGTH)

        res = TCP(server_response) / Raw(server_message)
        res.show()

        finish_first_handshake = self.create_acknowledge(res)
        finish_first_handshake.show()

        the_client_socket.send(bytes(finish_first_handshake[TCP]))
        the_client_socket.send(bytes(finish_first_handshake[Raw]))

        letter = syn_packet[Raw].load
        dot = finish_first_handshake[Raw].load
        authentic = letter + dot

        return finish_first_handshake, authentic

    def create_syn(self, server_port):
        """

        :param server_port: The server port
        :return: The SYN packet
        """

        syn_packet = TCP(flags=SYN, sport=RandShort(), dport=server_port, seq=RandShort()) / Raw(load=b"hi")

        syn_packet = syn_packet.__class__(bytes(syn_packet))

        return syn_packet

    def create_acknowledge(self, res):
        """
         Client response
        :param res: The ACK packet
        :return: The ACK packet
        """

        new_sport = res[TCP].dport
        new_dport = res[TCP].sport

        new_ack = res[TCP].seq + 1
        new_seq = res[TCP].ack + 1

        res[TCP].sport = new_sport
        res[TCP].dport = new_dport
        res[TCP].flags = ACK
        res[TCP].seq = new_seq
        res[TCP].ack = new_ack

        res[Raw].load = b"thanks"
        res = res.__class__(bytes(res))

        return res

    def secure_handshake(self, the_client_socket, auth):
        """

        :param the_client_socket:
        :param auth:
        """

        client_hello_packet = self.start_security()

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

        server_point = msg_key[TLS][TLSServerKeyExchange][ServerECDHNamedCurveParams].point

        client_key, cert, private_key = self.create_client_key()
        encryption_key = self.full_encryption(server_point, private_key)

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
        print(self.decrypt_data(encryption_key, auth, data_iv, data_c_t, data_tag))

        message = b'greetings!'
        some_data = self.encrypt_data(encryption_key, message, auth)
        print(some_data)
        data_msg = self.create_message(some_data)

        data_msg.show()
        the_client_socket.send(bytes(data_msg[TLS]))

        print(self.decrypt_data(encryption_key, auth, some_data[0], some_data[1], some_data[2]))

    def start_security(self):
        """
         Create client hello packet
        :return: Client hello packet
        """

        ch_packet = TLS(msg=TLSClientHello(ext=TLS_Ext_SupportedVersion_CH(versions=[TLS_N_VERSION, TLS_M_VERSION])))

        client_hello_packet = ch_packet
        client_hello_packet = client_hello_packet.__class__(bytes(client_hello_packet))
        client_hello_packet.show()

        return client_hello_packet

    def create_client_key(self):
        """
         Create client key exchange packet
        :return: TLS client key exchange packet
        """

        with open("certifacte.pem", "rb") as cert_file:
            server_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

        private_key, public_key_point = self.generate_the_point()

        client_parameters = ClientECDiffieHellmanPublic(ecdh_Yc=public_key_point)
        key_exc = (TLS(msg=TLSClientKeyExchange(exchkeys=client_parameters)) /
                   TLS(msg=TLSChangeCipherSpec()) /
                   TLS(msg=TLSFinished()))

        client_key = key_exc

        client_key = client_key.__class__(bytes(client_key))
        client_key.show()

        return client_key, server_cert, private_key

    def generate_the_point(self):
        """

        :return: The ECDH private key and public key point
        """

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Server public key point
        public_key_point = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        print(len(public_key_point), public_key)

        return private_key, public_key_point

    def full_encryption(self, server_point, private_key):
        """

        :param server_point:
        :param private_key:
        :return:
        """

        server_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_point)

        shared_secret = private_key.exchange(ec.ECDH(), server_key)
        derived_k_f = HKDF(algorithm=THE_SHA_256, length=32, salt=None, info=b'encryption key').derive(shared_secret)

        return derived_k_f

    def end_connection(self, basic_tcp, server_port):
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

    def encrypt_data(self, key, plaintext, associated_data):
        """

        :param key:
        :param plaintext:
        :param associated_data:
        :return:
        """

        # Generate a random 96-bit IV.
        iv = os.urandom(12)

        # Construct an AES-GCM Cipher object with the given key and a
        # randomly generated IV.
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        encryptor.authenticate_additional_data(associated_data)

        # Encrypt the plaintext and get the associated ciphertext.
        # GCM does not require padding.
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        print(encryptor.tag)

        return iv, ciphertext, encryptor.tag

    def decrypt_data(self, key, associated_data, iv, ciphertext, tag):
        """

        :param key:
        :param associated_data:
        :param iv:
        :param ciphertext:
        :param tag:
        :return:
        """

        # Construct a Cipher object, with the key, iv, and additionally the
        # GCM tag used for authenticating the message.
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()

        # We put associated_data back in or the tag will fail to verify
        # when we finalize the decryptor.
        decryptor.authenticate_additional_data(associated_data)

        # Decryption gets us the authenticated plaintext.
        # If the tag does not match an InvalidTag exception will be raised.
        return decryptor.update(ciphertext) + decryptor.finalize()

    def create_message(self, some_data):
        """

        :param some_data:
        :return:
        """

        full_data = some_data[0] + some_data[1] + some_data[2]
        data_packet = TLS(msg=TLSApplicationData(data=full_data))
        data_message = data_packet
        data_message = data_message.__class__(bytes(data_message))

        return data_message


def main():
    """
    Main function
    """

    client = Client()
    server_port = int(RandShort())
    server_ip = input("Enter the ip of the server\n")

    client.first_contact(server_ip, server_port)
    the_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    the_client_socket.connect((server_ip, server_port))

    finish_first_handshake, auth = client.the_pre_handshake(server_port, the_client_socket)
    client.secure_handshake(the_client_socket, auth)

    the_client_socket.close()


if __name__ == '__main__':
    main()
