from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import time
import socket

SYN = 2
ACK = 16
MY_IP = conf.route.route('0.0.0.0')[1]
TLS_M_VERSION = 0x0303
TLS_N_VERSION = 0x0304
RECOMMENDED_CIPHER = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val
MAX_MSG_LENGTH = 1024
EXCEPTIONAL_CASE_LENGTH = 4096
THE_SHA_256 = hashes.SHA256()
THE_BIG_LIST = {"0": "'", "1": ";", "2": "=", "3": '"', "4": "*", "5": "AND", "6": "SELECT", "7": "/", "8": "#",
                "9": "SQL", "10": "FROM", "11": "(", "12": ")", "13": "+", "14": "UNION", "15": "ALL", "16": ">",
                "17": "<", "18": "–dbs", "19": "-D", "20": "-T", "21": "-", "22": ".php", "23": "SLEEP", "24": "@@",
                "25": "CREATE USER", "26": "`", "27": "select", "28": "from", "29": "union", "30": "union",
                "31": "create user", "32": "sleep", "33": "all", "34": "and", "35": "INSERT", "36": "UPDATE",
                "37": "DELETE"}
PARAM_LIST = {"0": 0x0303, "1": 0x16, "2": 0x15, "3": 0x14, "4": 0x1}
SECP = [0x6a6a, 0x001d, 0x0017, 0x0018]
SIGNATURE_ALGORITHIM = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
KEY = {}


class Client:

    def __init__(self, the_client_socket: socket):
        self.__the_client_socket = the_client_socket

    def run(self):
        """

        """
        try:
            server_ip, server_port = self.format_socket()
            res, server_port = self.first_contact(server_ip, server_port)

            if res[Raw].load == b'Accept':

                time.sleep(2)

                self.initialize_handshakes(server_ip, server_port)
                time.sleep(2)

                #if KEY['encryption'][0] != 1:
                 #   self.communicate()

            else:
                print("TO BAD YOU ARE BANNED!")

        except ConnectionRefusedError:
            print("Connection refused check your internet")

        except KeyboardInterrupt:
            print("Leaving the game")

    def format_socket(self):
        """

        :return:
        """

        server_port = self.choose_port()
        server_ip = self.find_ip()

        return server_ip, server_port

    def choose_port(self):
        """

        :return:
        """

        server_port = int(RandShort())
        if server_port == 443:
            server_port += 1

        return server_port

    def find_ip(self):
        """

        :return:
        """
        while True:
            server_ip = input("Enter the ip of the server\n")

            if self.ip_v_four_format(server_ip) and not self.empty_string(server_ip):
                return server_ip

    def empty_string(self, message):
        """

        :param message:
        :return:
        """
        return message is None or ' ' in message or message == ''

    def ip_v_four_format(self, ip_address):
        """

        :param ip_address:
        :return:
        """
        return (ip_address.count('.') == 3 and ''.join(ip_address.split('.')).isnumeric() and
                len(''.join(ip_address.split('.'))) <= 12)

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

        while True:
            vert = sniff(count=1, lfilter=self.filter_tcp)
            vert[0].show()

            if vert[0][IP].src != server_ip:
                print("Send an emergency request")
                tcp_packet[Raw].load = b'URGENT'

                tcp_packet[TCP].seq = RandShort()
                sendp(tcp_packet)

            else:
                break

        res = vert[0]

        return res, server_port

    def filter_tcp(self, packets):
        """
         Check if the packet received is a TCP packet
        :param packets: The packet
        :return: If the packet has TCP in it
        """

        return TCP in packets and Raw in packets and \
            (packets[Raw].load == b'Accept' or packets[Raw].load == b'Denied')

    def initialize_handshakes(self, server_ip, server_port):
        """

        :param server_ip:
        :param server_port:
        """

        while True:
            try:
                time.sleep(2)
                self.__the_client_socket.connect((server_ip, server_port))

                KEY["encryption"] = self.connection_handshakes(server_port)
                break

            except KeyboardInterrupt:
                print("refused to play")

            except ConnectionRefusedError:
                print("Waiting")
                continue

    def connection_handshakes(self, server_port):
        """

        :param server_port:
        """

        finish_first_handshake, auth = self.the_pre_handshake(server_port)
        key = self.secure_handshake(auth)

        return key, auth

    def the_pre_handshake(self, server_port):
        """
         Initiate the three-way handshake
        :param server_port: The chosen server port
        :return: The ack packet and the authentic client associate
        """
        syn_packet = self.create_syn(server_port)
        time.sleep(2)

        while True:
            self.__the_client_socket.settimeout(3)
            try:
                time.sleep(2)
                self.__the_client_socket.send(bytes(syn_packet[TCP]))

                server_response = self.__the_client_socket.recv(MAX_MSG_LENGTH)
                server_message = self.__the_client_socket.recv(MAX_MSG_LENGTH)
                break

            except socket.timeout:
                print('retry')

        self.__the_client_socket.setblocking(True)
        res = TCP(server_response) / Raw(server_message)

        finish_first_handshake = self.create_acknowledge(res)
        self.__the_client_socket.send(bytes(finish_first_handshake[TCP]))

        self.__the_client_socket.send(bytes(finish_first_handshake[Raw]))
        time.sleep(2)

        letter = syn_packet[Raw].load[0:2]
        dot = finish_first_handshake[Raw].load[0:4]

        authentic = letter + dot

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

    def secure_handshake(self, auth):
        """
         Start the secure handshake with the server
        :param auth: The authentic data
        """

        client_hello_packet = self.start_security()
        self.__the_client_socket.send(bytes(client_hello_packet[TLS]))

        server_hello = self.__the_client_socket.recv(MAX_MSG_LENGTH)
        cert = self.__the_client_socket.recv(EXCEPTIONAL_CASE_LENGTH)
        key = self.__the_client_socket.recv(MAX_MSG_LENGTH)

        msg_s = TLS(server_hello)
        msg_cert = TLS(cert)
        msg_key = TLS(key)

        msg_cert.show()

        if TLSServerHello in msg_s and TLSCertificate in msg_cert and TLSServerKeyExchange in msg_key:

            server_point = msg_key[TLS][TLSServerKeyExchange][ServerECDHNamedCurveParams].point

            client_key, cert, private_key = self.create_client_key()
            encryption_key = self.full_encryption(server_point, private_key)

            self.__the_client_socket.send(bytes(client_key[TLS]))
            server_final = self.__the_client_socket.recv(MAX_MSG_LENGTH)

            msg_s_f = TLS(server_final)

            if self.is_there_an_alert(msg_s_f):
                print("YOU ARE BANNED")
                return

            else:
                data_iv, data_c_t, data_tag = self.recieve_data()

                print(self.decrypt_data(encryption_key, auth, data_iv, data_c_t, data_tag))
                message = b'greetings!'

                some_data = self.encrypt_data(encryption_key, message, auth)
                data_msg = self.create_message(some_data)

                if type(data_msg) is list:
                    for i in range(0, len(data_msg)):
                        message = data_msg[i]
                        self.__the_client_socket.send(bytes(message[TLS]))

                else:
                    self.__the_client_socket.send(bytes(data_msg[TLS]))

                print(self.decrypt_data(encryption_key, auth, some_data[0], some_data[1], some_data[2]))

                details = self.details_entry(encryption_key, auth)

                self.__the_client_socket.send(bytes(details[TLS]))

                return encryption_key
        else:
            alert_message = self.send_alert()
            self.__the_client_socket.send(bytes(alert_message[TLS]))
            i = 1
            while True:  # THIS WILL BE REMOVED THIS IS AN EMERGENCY PAUSE
                try:
                    if i == 1:
                        print("ALERT ALERT")
                        i += 1
                except KeyboardInterrupt:
                    break

        return 1

    def start_security(self):
        """
         Create client hello packet
        :return: Client hello packet
        """

        ch_packet = TLS(msg=TLSClientHello(ext=TLS_Ext_SupportedVersion_CH(versions=[TLS_N_VERSION, TLS_M_VERSION]) /
                        TLS_Ext_SignatureAlgorithms(sig_algs=SIGNATURE_ALGORITHIM) / TLS_Ext_RenegotiationInfo() /
                        TLS_Ext_ExtendedMasterSecret() / TLS_Ext_SupportedPointFormat() /
                        TLS_Ext_SupportedGroups(groups=SECP)))

        client_hello_packet = ch_packet
        client_hello_packet = client_hello_packet.__class__(bytes(client_hello_packet))

        return client_hello_packet

    def create_client_key(self):
        """
         Create client key exchange packet
        :return: TLS client key exchange packet
        """

        with open("Certificates\\certificate1.pem", "rb") as cert_file:
            server_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

        private_key, public_key_point = self.generate_the_point()

        client_parameters = ClientECDiffieHellmanPublic(ecdh_Yc=public_key_point)
        key_exc = (TLS(msg=TLSClientKeyExchange(exchkeys=client_parameters)) /
                   TLS(msg=TLSChangeCipherSpec()) /
                   TLS(msg=TLSFinished()))

        client_key = key_exc
        client_key = client_key.__class__(bytes(client_key))

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

    def recieve_data(self):
        """
         Dissect the data received from the server
        :return: The data iv, data and tag
        """

        data_pack = TLS(self.__the_client_socket.recv(MAX_MSG_LENGTH))

        data = data_pack[TLS][TLSApplicationData].data
        data_iv = data[:12]

        data_tag = data[len(data) - 16:len(data)]
        data_c_t = data[12:len(data) - 16]

        return data_iv, data_c_t, data_tag

    def encrypt_data(self, key, plaintext, associated_data):
        """
         Encrypt data before sending it to the client
        :param key: The server encryption key
        :param plaintext: The data which will be encrypted
        :param associated_data: Data which is associated with yet not encrypted
        :return: The iv, the encrypted data and the encryption tag
        """

        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()

        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

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

        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(associated_data)

        return decryptor.update(ciphertext) + decryptor.finalize()

    def create_message(self, some_data):
        """
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """

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

         Turn the data into a proper message
        :param key: The key
        :param auth: The authenticator
        :return: The full data message
        """
        while True:
            user = input("Enter your username\n")
            passw = input("Enter your password\n")

            if self.empty_string(user) or self.empty_string(passw):
                print("Please enter the requested information")

            elif user == 'EXIT' or passw == 'EXIT':
                print("YOU CAN'T EXIT AT LOGIN!")

            elif self.malicious_message(user) or self.malicious_message(passw):
                print("Don't mess with Shmulik")

            else:
                break

        user = user.encode()
        passw = passw.encode()

        credentials = user + " ".encode() + passw
        encrypted_credentials = self.encrypt_data(key, credentials, auth)

        data = encrypted_credentials
        pack = self.create_message(data)

        return pack

    def is_there_an_alert(self, message):
        """

        :param message:
        :return:
        """

        return TLSAlert in message

    def send_alert(self):
        """

        :return:
        """

        alert = TLS(msg=TLSAlert(level=2, descr=40))
        alert = alert.__class__(bytes(alert))

        return alert

    def malicious_message(self, message):
        """

        :param message:
        :return:
        """

        for index in range(0, len(THE_BIG_LIST)):
            if THE_BIG_LIST.get(str(index)) in message:
                return True

        if len(message) > 50:
            return True

        if message.isnumeric() and sys.maxsize <= int(message):
            return True

        return False

    def communicate(self, location):
        """
        :param location:
        """

        try:
            if 1 not in KEY:
                key, auth = KEY['encryption'][0], KEY['encryption'][1]
                message = str(location)

                if not self.malicious_message(message):
                    message = message.encode()
                #    print(message)

                    data = [self.encrypt_data(key, message, auth)]
                    full_msg = self.create_message(data)

                    if type(full_msg) is list:
                        for index in range(0, len(full_msg)):
                            message = full_msg[index]
                            self.__the_client_socket.send(bytes(message[TLS]))

                    else:
                        self.__the_client_socket.send(bytes(full_msg[TLS]))

                    if message == "EXIT":
                        self.__the_client_socket.close()
                        return
                else:
                    print("ILLEGAL")

        except ConnectionResetError:
            time.sleep(0.1)

        except ConnectionRefusedError:
            print("Retrying")

        except ConnectionAbortedError:
            self.__the_client_socket.close()
            return

        except KeyboardInterrupt:
            print("Server is shutting down")
            self.__the_client_socket.close()
            return


def main():
    """
    Main function
    """
    the_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    client = Client(the_client_socket)
    client.run()


if __name__ == '__main__':
    main()
