from scapy.layers.dns import *
from scapy.layers.tls.all import *
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
EXCEPTIONAL_CASE_LENGTH = 5000
THE_SHA_256 = hashes.SHA256()
PARAM_LIST = {"0": 0x0303, "1": 0x16, "2": 0x15, "3": 0x14, "4": 0x1}
SECP = [0x6a6a, 0x001d, 0x0017, 0x0018]
SIGNATURE_ALGORITHIM = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
AUTHORITY = []
KEY = {}
MSG_TCP_PACK = 56


class ClientHandshake:

    def __init__(self, client_socket: socket, server_ip: str, server_port: int):
        self.__the_client_socket = client_socket
        self.__server_ip = server_ip

        self.__server_port = server_port
        self.__messages = {"TLS_VALID_HELLO": (0, TLS()), "FINISH": (0, TLS()), "TLS_FIRST_DATA": (0, b"")}

        self.__authority = []
        self.__key = {}

    def run(self):
        """

        """
        while True:
            try:
                KEY["encryption"] = self.connection_handshakes()
                if KEY["encryption"]:
                    return KEY["encryption"]

                else:
                    return
            except KeyboardInterrupt:
                print("refused to play")

            except ConnectionRefusedError:
                print("Waiting")
                continue

            except ConnectionAbortedError:
                print("Retrying")

    def connection_handshakes(self):
        """

        """
        while True:
            try:
                if not AUTHORITY:
                    important = self.the_pre_handshake()

                    if not important:
                        pass

                    else:
                        AUTHORITY.append(important)

                else:
                    print("success")
                    auth = AUTHORITY[0]
                    key = self.secure_handshake(auth)

                    if not key:
                        pass

                    else:
                        return key, auth

            except ConnectionAbortedError:
                self.__messages = {"TLS_VALID_HELLO": (0, TLS()), "FINISH": (0, TLS()), "TLS_FIRST_DATA": (0, b"")}
                self.__authority = []
                self.__key = {}

            except ConnectionResetError:
                self.__messages = {"TLS_VALID_HELLO": (0, TLS()), "KEYS": (0, TLS()), "TLS_FIRST_DATA": (0, b"")}
                self.__authority = []
                self.__key = {}

    def the_pre_handshake(self):
        """
         Initiate the three-way handshake
        :return: The ack packet and the authentic client associate
        """
        syn_packet = self.create_syn()

        while True:
            try:
                self.__the_client_socket.send(bytes(syn_packet[TCP]))

                server_response = self.__the_client_socket.recv(MSG_TCP_PACK)

                if not server_response:
                    return

                else:
                    break

            except socket.timeout:
                print('retry')
                return

        res = TCP(server_response)

        finish_first_handshake = self.create_acknowledge(res)
        self.__the_client_socket.send(bytes(finish_first_handshake[TCP]))

        letter = syn_packet[Raw].load[0:2]
        dot = finish_first_handshake[Raw].load[0:4]

        authentic = letter + dot

        return authentic

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

        server_hello = self.handle_responses()

        if server_hello or self.server_hello_legit(self.__messages["TLS_VALID_HELLO"][1]):
            print("Successfully authenticated communication!")
            server_hello = self.__messages["TLS_VALID_HELLO"][1]

            server_point = server_hello[TLS][TLSServerKeyExchange][ServerECDHNamedCurveParams].point
            client_key, private_key = self.create_client_key()

            encryption_key = self.full_encryption(server_point, private_key)
            self.__the_client_socket.send(bytes(client_key[TLS]))

            server_final = self.handle_responses()
            msg_s_f = TLS(server_final)

            if self.is_there_an_alert(msg_s_f):
                print("YOU ARE BANNED")
                return

            else:
                data = self.recieve_data()

                if not data:
                    return

                else:

                    data_iv, data_c_t, data_tag = data[0], data[1], data[2]

                    if self.__messages["TLS_FIRST_DATA"][0] == 0:
                        first_message = self.decrypt_data(encryption_key, auth, data_iv, data_c_t, data_tag)
                        self.__messages["TLS_FIRST_DATA"] = 1, first_message

                        message = b'greetings!'

                        some_data = self.encrypt_data(encryption_key, message, auth)
                        data_msg = self.create_message(some_data)

                        if type(data_msg) is list:
                            for i in range(0, len(data_msg)):
                                message = data_msg[i]
                                self.__the_client_socket.send(bytes(message[TLS]))

                        else:
                            self.__the_client_socket.send(bytes(data_msg[TLS]))

                        print("Secrecy has been successfully achieved, good luck decrypting with third parties! :D")

                        return encryption_key
        else:
            alert_message = self.send_alert()
            self.__the_client_socket.send(bytes(alert_message[TLS]))
            return

    def start_security(self):
        """
         Create client hello packet
        :return: Client hello packet
        """

        ch_packet = TLS(msg=TLSClientHello(ext=TLS_Ext_SupportedVersion_CH(versions=[TLS_N_VERSION, TLS_M_VERSION]) /
                                               TLS_Ext_SignatureAlgorithms(
                                                   sig_algs=SIGNATURE_ALGORITHIM) / TLS_Ext_RenegotiationInfo() /
                                               TLS_Ext_ExtendedMasterSecret() / TLS_Ext_SupportedPointFormat() /
                                               TLS_Ext_SupportedGroups(groups=SECP)))

        client_hello_packet = ch_packet
        client_hello_packet = client_hello_packet.__class__(bytes(client_hello_packet))

        return client_hello_packet

    def handle_responses(self):
        """

        :return:
        """

        server_hello = self.receive_server_hello()
        if server_hello:
            return server_hello

        finish_message = self.receive_finish_message()
        if finish_message:
            return finish_message

    def receive_server_hello(self):
        """

        :return:
        """

        try:
            if self.__messages["TLS_VALID_HELLO"][0] == 0:
                server_hello = self.__the_client_socket.recv(EXCEPTIONAL_CASE_LENGTH)
                if not server_hello:
                    return

                else:
                    server_hello = TLS(server_hello)
                    if self.server_hello_legit(server_hello):
                        self.__messages["TLS_VALID_HELLO"] = 1, server_hello

                        return server_hello

                    else:
                        return

            else:
                return

        except socket.timeout:
            return

    def server_hello_legit(self, server_hello):
        """

        :param server_hello:
        :return:
        """

        return (TLS in server_hello and TLSServerHello in server_hello and TLSCertificate in server_hello and
                TLSServerKeyExchange in server_hello and
                server_hello[TLS][TLSServerHello][TLS_Ext_SupportedVersion_SH].version == TLS_M_VERSION and
                server_hello[TLS][TLSServerHello].cipher == RECOMMENDED_CIPHER)

    def receive_finish_message(self):
        """

        :return:
        """

        try:
            if self.__messages["FINISH"][0] == 0 and self.__messages["TLS_VALID_HELLO"][0] == 1:
                finish = self.__the_client_socket.recv(MAX_MSG_LENGTH)

                if not finish:

                    return

                else:
                    finish = TLS(finish)

                    if self.finish_legit(finish):
                        self.__messages["FINISH"] = 1, finish
                        return finish

                    else:
                        return

            else:
                return

        except socket.timeout:
            return

    def finish_legit(self, finish):
        """

        :param finish:
        :return:
        """

        return TLS in finish and TLSChangeCipherSpec in finish and TLSFinished in finish

    def create_client_key(self):
        """
         Create client key exchange packet
        :return: TLS client key exchange packet
        """

        private_key, public_key_point = self.generate_the_point()

        client_parameters = ClientECDiffieHellmanPublic(ecdh_Yc=public_key_point)
        key_exc = (TLS(msg=TLSClientKeyExchange(exchkeys=client_parameters)) /
                   TLS(msg=TLSChangeCipherSpec()) /
                   TLS(msg=TLSFinished()))

        client_key = key_exc
        client_key = client_key.__class__(bytes(client_key))

        return client_key, private_key

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
        self.__the_client_socket.settimeout(0.1)

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

        except socket.timeout:
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