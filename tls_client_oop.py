import sys
from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
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
MAX_MSG_LENGTH = 1024
THE_SHA_256 = hashes.SHA256()
THE_BIG_LIST = {"0": "'", "1": ";", "2": "=",
                "3": '"', "4": "*", "5": "AND",
                "6": "SELECT", "7": "/", "8": "#",
                "9": " ", "10": "FROM", "11": "(", "12": ")",
                "13": "+", "14": "UNION", "15": "ALL",
                "16": ">", "17": "<", "18": "–dbs", "19": "-D",
                "20": "-T", "21": "-", "22": ".php", "23": "SLEEP",
                "24": "@@", "25": "CREATE USER", "26": "`", "27": "select",
                "28": "from", "29": "union", "30": "union", "31": "create user",
                "32": "sleep", "33": "all", "34": "and", "35": "INSERT", "36": "UPDATE",
                "37": "DELETE"}
PARAM_LIST = {"0": 0x0303, "1": 0x16, "2": 0x15, "3": 0x14,
              "4": 0x1}


class Client:

    def __init__(self):
        pass

    def first_contact(self, server_ip, server_port):
        """
         Get in contact with the server by sending a TCP packet to it
        :param server_ip: The server's ip
        :param server_port: The port the client will connect to
        """

        if server_ip == MY_IP:
            server_mac = get_if_hwaddr(conf.iface)
            layer2 = Ether(src=server_mac, dst=server_mac)

        else:
            server_mac = getmacbyip(server_ip)
            client_mac = get_if_hwaddr(conf.iface)
            layer2 = Ether(src=client_mac, dst=server_mac)

        tcp_packet = (layer2 / IP(src=MY_IP, dst=server_ip) /
                      TCP(sport=RandShort(), dport=server_port) /
                      Raw(load=b'Logged'))

        tcp_packet = tcp_packet.__class__(bytes(tcp_packet))
        tcp_packet.show()
        sendp(tcp_packet)

        vert = sniff(count=1, lfilter=self.filter_tcp)
        vert[0].show()
        res = vert[0]

        return res

    def filter_tcp(self, packets):
        """
         Check if the packet received is a TCP packet
        :param packets: The packet
        :return: If the packet has TCP in it
        """

        return TCP in packets and Raw in packets and \
            (packets[Raw].load == b'Accept' or packets[Raw].load == b'Denied')

    def the_pre_handshake(self, server_port, the_client_socket):
        """
         Initiate the three-way handshake
        :param server_port: The chosen server port
        :param the_client_socket:
        :return: The ack packet and the authentic client associate
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

        finisher = finish_first_handshake.copy()
        self.end_the_connection(finisher, server_port, the_client_socket)

        return finish_first_handshake, authentic

    def create_syn(self, server_port):
        """
         Create the syn packet
        :param server_port: The server port
        :return: The SYN packet
        """

        syn_packet = TCP(flags=SYN, sport=RandShort(), dport=server_port, seq=RandShort()) / Raw(load=b"hi")

        syn_packet = syn_packet.__class__(bytes(syn_packet))

        return syn_packet

    def create_acknowledge(self, res):
        """
         Create the ACK packet
        :param res: The SYN + ACK packet
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
         Start the secure handshake with the server
        :param the_client_socket: The client socket
        :param auth: The authentic data
        """

        client_hello_packet = self.start_security()
        client_hello_packet.show()
        print(bytes(client_hello_packet[TLS]), "\n", len(bytes(client_hello_packet[TLS])))
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

        if TLSServerHello in msg_s and TLSCertificate in msg_cert and TLSServerKeyExchange in msg_key:

            server_point = msg_key[TLS][TLSServerKeyExchange][ServerECDHNamedCurveParams].point

            client_key, cert, private_key = self.create_client_key()
            encryption_key = self.full_encryption(server_point, private_key)

            the_client_socket.send(bytes(client_key[TLS]))
            server_final = the_client_socket.recv(MAX_MSG_LENGTH)
            msg_s_f = TLS(server_final)
            msg_s_f.show()

            if self.is_there_an_alert(msg_s_f):
                print("YOU ARE BANNED")
                return

            else:
                data_iv, data_c_t, data_tag = self.recieve_data(the_client_socket)

                print(data_iv, data_c_t, data_tag)
                print("==============", "\n", encryption_key, "\n", "==============")
                print(self.decrypt_data(encryption_key, auth, data_iv, data_c_t, data_tag))

                message = b'greetings!'
                some_data = self.encrypt_data(encryption_key, message, auth)
                print(some_data)
                data_msg = self.create_message(some_data)

                if type(data_msg) is list:
                    for i in range(0, len(data_msg)):
                        message = data_msg[i]
                        message.show()
                        the_client_socket.send(bytes(message[TLS]))

                else:
                    data_msg.show()
                    the_client_socket.send(bytes(data_msg[TLS]))

                print(self.decrypt_data(encryption_key, auth, some_data[0], some_data[1], some_data[2]))

                details = self.details_entry(encryption_key, auth)

                if details[0] == 0 and details[1] == 1:
                    print("YOU WERE BANNED FOR USING HTML")

                else:
                    the_client_socket.send(bytes(details[0][TLS]))
                    the_client_socket.send(bytes(details[1][TLS]))
        else:
            alert_message = self.send_alert()
            the_client_socket.send(bytes(alert_message[TLS]))

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
         Generate the ECDH private key and public key
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
         Create the client encryption key
        :param server_point: The servers point
        :param private_key: The client private key
        :return: The server encryption key
        """

        server_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_point)

        shared_secret = private_key.exchange(ec.ECDH(), server_key)
        derived_k_f = HKDF(algorithm=THE_SHA_256, length=32, salt=None, info=b'encryption key').derive(shared_secret)

        return derived_k_f

    def recieve_data(self, the_client_socket):
        """
         Dissect the data received from the server
        :param the_client_socket: The client socket
        :return: The data iv, data and tag
        """

        data_pack = TLS(the_client_socket.recv(MAX_MSG_LENGTH))
        data_pack.show()
        data = data_pack[TLS][TLSApplicationData].data

        print("Will decrypt", data)
        data_iv = data[:12]
        data_tag = data[len(data) - 16:len(data)]
        data_c_t = data[12:len(data) - 16]

        return data_iv, data_c_t, data_tag

    def end_the_connection(self, finisher, server_port, client_socket):
        """
         Terminate a tcp connection
        :param server_port: Servers port
        :param finisher: Simple TCP packet with ACK flag
        """

        finisher[TCP].flags = FIN
        client_socket.send(bytes(finisher[TCP]))

        server_ack = client_socket.recv(MAX_MSG_LENGTH)
        g = TCP(server_ack)
        server_fin = client_socket.recv(MAX_MSG_LENGTH)
        m = TCP(server_fin)

        c = m.copy()
        c[TCP].ack = c[TCP].ack + 1
        c[TCP].flags = ACK
        c[TCP].sport = c[TCP].dport
        c[TCP].dport = server_port
        client_socket.send(bytes(c[TCP]))


    def encrypt_data(self, key, plaintext, associated_data):
        """
         Encrypt data before sending it to the client
        :param key: The server encryption key
        :param plaintext: The data which will be encrypted
        :param associated_data: Data which is associated with yet not encrypted
        :return: The iv, the encrypted data and the encryption tag
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
         Decrypt the data recieved by the client
        :param key: The server encryption key
        :param associated_data: The data associated with the message
        :param iv: The iv
        :param ciphertext: The encrypted data
        :param tag: The encryption tag
        :return: The decrypted data
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
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """
        print(type(some_data))
        if type(some_data) is not list:
            full_data = some_data[0] + some_data[1] + some_data[2]
            data_packet = TLS(msg=TLSApplicationData(data=full_data))
            data_message = data_packet
            data_message = data_message.__class__(bytes(data_message))

        else:
            data_pack_list = []

            for i in range(0, len(some_data)):
                first_data = some_data[i][0] + some_data[i][1] + some_data[i][2]
                data_packet = TLS(msg=TLSApplicationData(data=first_data))
                data_packet = data_packet.__class__(bytes(data_packet))
                data_pack_list.append(data_packet)

            return data_pack_list

        return data_message

    def details_entry(self, key, auth):
        """

        Args:
            key:
            auth:

        Returns:

        """
        user = input("Enter your username\n")
        passw = input("Enter your password\n")

        for i in range(0, len(THE_BIG_LIST)):

            if THE_BIG_LIST.get(str(i)) in passw or \
               THE_BIG_LIST.get(str(i)) in user:
                return 0, 1

        if len(user) > 50 or len(passw) > 50:
            return 0, 1

        if ((user.isnumeric() and sys.maxsize <= int(user)) or
                (passw.isnumeric() and sys.maxsize <= int(passw))):
            return 0, 1

        user = user.encode()
        passw = passw.encode()

        encyrpted_user = self.encrypt_data(key, user, auth)
        encrypted_passw = self.encrypt_data(key, passw, auth)
        data = [encyrpted_user, encrypted_passw]
        pack = self.create_message(data)

        return pack

    def is_there_an_alert(self, message):

        return TLSAlert in message

    def send_alert(self):

        alert = TLS(msg=TLSAlert(level=2, descr=40))
        alert = alert.__class__(bytes(alert))

        return alert
    
    def run(self):
        pass


def main():
    """
    Main function
    """

    client = Client()
    server_port = int(RandShort())
    server_ip = input("Enter the ip of the server\n")

    res = client.first_contact(server_ip, server_port)
    if res[Raw].load == b'Accept':

        the_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        the_client_socket.connect((server_ip, server_port))

        finish_first_handshake, auth = client.the_pre_handshake(server_port, the_client_socket)
        client.secure_handshake(the_client_socket, auth)

        the_client_socket.close()

    else:
        print("TO BAD YOU ARE BANNED!")


if __name__ == '__main__':
    main()
