from scapy.layers.dns import *
from scapy.layers.tls.all import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
import os

SYN = 2
ACK = 16
TLS_M_VERSION = 0x0303
TLS_N_VERSION = 0x0304
RECOMMENDED_CIPHER = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val
MAX_MSG_LENGTH = 1024
EXCEPTIONAL_CASE_LENGTH = 4096
THE_SHA_256 = hashes.SHA256()
PARAM_LIST = {"0": 0x0303, "1": 0x16, "2": 0x15, "3": 0x14, "4": 0x1}
SECP = [0x6a6a, 0x001d, 0x0017, 0x0018]
SIGNATURE_ALGORITHIM = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
KEY = {}


class ClientHandshake:

    def __init__(self, client_socket: socket, server_ip: str, server_port: int):
        self.__the_client_socket = client_socket
        self.__server_ip = server_ip
        self.__server_port = server_port

    def run(self):
        """

        """

        while True:
            try:
                time.sleep(2)
                self.__the_client_socket.connect((self.__server_ip, self.__server_port))

                KEY["encryption"] = self.connection_handshakes()

                return KEY["encryption"]

            except KeyboardInterrupt:
                print("refused to play")

            except ConnectionRefusedError:
                print("Waiting")
                continue

    def connection_handshakes(self):
        """

        """
        while True:
            important = self.the_pre_handshake()
            if not important:
                pass
            else:
                auth = important[1]
                key = self.secure_handshake(auth)

                return key, auth

    def the_pre_handshake(self):
        """
         Initiate the three-way handshake
        :return: The ack packet and the authentic client associate
        """
        syn_packet = self.create_syn()
        self.__the_client_socket.settimeout(3)

        while True:
            try:
                self.__the_client_socket.send(bytes(syn_packet[TCP]))

                server_response = self.__the_client_socket.recv(MAX_MSG_LENGTH)
                server_message = self.__the_client_socket.recv(MAX_MSG_LENGTH)

                if not server_response and not server_message:
                    return

                else:
                    res = TCP(server_response) / Raw(server_message)

                    finish_first_handshake = self.create_acknowledge(res)
                    self.__the_client_socket.send(bytes(finish_first_handshake[TCP]))

                    self.__the_client_socket.send(bytes(finish_first_handshake[Raw]))
                    time.sleep(2)

                    letter = syn_packet[Raw].load[0:2]
                    dot = finish_first_handshake[Raw].load[0:4]

                    authentic = letter + dot

                    return finish_first_handshake, authentic

            except socket.timeout:
                print('retry')

    def create_syn(self):
        """
         Create the syn packet
        :return: The SYN packet
        """

        syn_packet = TCP(flags=SYN, sport=RandShort(), dport=self.__server_port, seq=RandShort()) / Raw(load=b"flying")

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

        res[Raw].load = b"ocean"
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

        if TLSServerHello in msg_s and TLSCertificate in msg_cert and TLSServerKeyExchange in msg_key:

            print("Successfully authenticated communication!")
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
                print("Secrecy has been successfully achieved, good luck decrypting with third parties! :D")

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

        with open("Certificates\\certificate3.pem", "rb") as cert_file:
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
        try:
            data_pack = self.__the_client_socket.recv(MAX_MSG_LENGTH)

            if not data_pack:
                return

            else:
                data_pack = TLS(data_pack)
                data = data_pack[TLS][TLSApplicationData].data
                data_iv = data[:12]

                data_tag = data[len(data) - 16:len(data)]
                data_c_t = data[12:len(data) - 16]

            return data_iv, data_c_t, data_tag

        except IndexError:
            return

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

    def is_there_an_alert(self, message):
        """

        :param message:
        :return:
        """

        return TLS in message and TLSAlert in message

    def send_alert(self):
        """

        :return:
        """

        alert = TLS(msg=TLSAlert(level=2, descr=40))
        alert = alert.__class__(bytes(alert))

        return alert
