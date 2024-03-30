# NOTE THIS CODE DOES NOT INCLUDE LOGIN, THREADING THIS IS A GENERAL HANDSHAKE!
from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib
import socket

SYN = 2
ACK = 16
MSS = [("MSS", 1460)]
N = RandShort()  # Key base number
TLS_MID_VERSION = 0x0303
TLS_NEW_VERSION = 0x0304
RECOMMENDED_CIPHER = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val
H_NAME = "Cyber-Offensive"
KEY_ENC = serialization.Encoding.X962
FORMAT_PUBLIC = serialization.PublicFormat.UncompressedPoint
THE_PEM = serialization.Encoding.PEM
PRIVATE_OPENSSL = serialization.PrivateFormat.TraditionalOpenSSL
GOOD_PAD = PSS(MGF1(hashes.SHA256()), PSS.MAX_LENGTH)
MAX_MSG_LENGTH = 1024
EXCEPTIONAL_CASE_LENGTH = 4096
THE_SHA_256 = hashes.SHA256()
SECP = 0x0017
SIGNATURE_ALGORITHIM = 0x0401
AUTHORITY = []
PRIVATE_KEY = []
MESSAGES = {"TLS_VALID_HELLO": (0, TLS()), "KEYS": (0, TLS()), "TLS_FIRST_DATA": (0, TLS())}


class ServerHandshake:

    def __init__(self, client_socket: socket):
        self.__client_socket = client_socket

    def run(self):
        """

        :return:
        """

        while True:
            if not AUTHORITY:
                auth = self.first_handshake()
                if not auth:
                    pass

                else:
                    AUTHORITY.append(auth)

            else:
                print("success")
                auth = AUTHORITY[0]
                enc_key = self.secure_handshake(auth)

                if enc_key:
                    break

                else:
                    pass

        return enc_key, auth

    def first_handshake(self):
        """
         The tcp handshake
        :return: The ack packet and the server port used the client will use
        """

        while True:
            first_packet = self.__client_socket.recv(MAX_MSG_LENGTH)
            first_data = self.__client_socket.recv(MAX_MSG_LENGTH)

            if not first_packet and not first_data:
                print("retrying")
                pass

            else:
                syn_packet = TCP(first_packet)
                syn_data = Raw(first_data)

                syn_packet = syn_packet / syn_data
                clients_letter = syn_packet[Raw].load[0:2]

                response = self.create_response(syn_packet)
                self.__client_socket.send(bytes(response[TCP]))

                time.sleep(2)
                self.__client_socket.send(bytes(response[Raw]))

                last_pack = self.__client_socket.recv(MAX_MSG_LENGTH)
                last_pack_data = self.__client_socket.recv(MAX_MSG_LENGTH)

                ack_packet = TCP(last_pack) / Raw(last_pack_data)

                clients_dot = ack_packet[Raw].load[0:4]
                auth = clients_letter + clients_dot

                return auth

    def create_response(self, syn_packet):
        """
         Server response
        :param syn_packet: The SYN packet
        :return: packet_auth
        """

        packet_auth = syn_packet.copy()
        new_sport = packet_auth[TCP].dport
        new_dport = packet_auth[TCP].sport

        packet_auth[TCP].ack = packet_auth[TCP].seq + 1
        packet_auth[TCP].flags = SYN + ACK

        packet_auth[TCP].seq = RandShort()
        packet_auth[TCP].sport = new_sport

        packet_auth[TCP].dport = new_dport
        packet_auth[TCP].options = MSS

        packet_auth[Raw].load = f"helloSEC".encode()
        packet_auth = self.prepare_packet_structure(packet_auth)

        return packet_auth

    def prepare_packet_structure(self, the_packet):
        """

        :param the_packet:
        :return:
        """

        return the_packet.__class__(bytes(the_packet))

    def secure_handshake(self, auth):
        """
         The TLS handshake
        :param auth: The associate data
        """

        t_client_hello = self.handle_responses()

        if t_client_hello or self.client_hello_legit(MESSAGES["TLS_VALID_HELLO"][1]):
            keys_and_privates = self.server_authentication()

            if MESSAGES["TLS_VALID_HELLO"][0] == 1 and MESSAGES["KEYS"][0] == 1:
                keys, private_key = MESSAGES["KEYS"][1], PRIVATE_KEY[0]
                print(type(keys))
                keys.show()
                encryption_key = self.exchange_server_key(keys, private_key, auth)

                if encryption_key:
                    return encryption_key

                else:
                    return

            else:
                return

    def handle_responses(self):
        """

        :return:
        """

        client_hello = self.receive_client_hello()
        if client_hello:
            return client_hello

        client_keys = self.receive_client_keys()
        if client_keys:
            return client_keys

    def receive_client_hello(self):
        """

        :return:
        """

        try:
            if MESSAGES["TLS_VALID_HELLO"][0] == 0:
                self.__client_socket.settimeout(0.5)
                t_client_hello = self.__client_socket.recv(MAX_MSG_LENGTH)

                if not t_client_hello:

                    return

                else:
                    t_client_hello = TLS(t_client_hello)
                    t_client_hello.show()

                    if self.client_hello_legit(t_client_hello):
                        MESSAGES["TLS_VALID_HELLO"] = 1, t_client_hello
                        return t_client_hello

                    else:

                        print("Client has not used tls properly")

                        self.send_alert()

                        return

            else:
                return

        except socket.timeout:
            return

    def client_hello_legit(self, t_client_hello):
        """

        :param t_client_hello:
        :return:
        """

        return (TLS in t_client_hello and (TLSClientHello in t_client_hello and TLS_MID_VERSION in
                t_client_hello[TLS][TLSClientHello][TLS_Ext_SupportedVersion_CH].versions and
                RECOMMENDED_CIPHER in t_client_hello[TLS][TLSClientHello].ciphers))

    def receive_client_keys(self):
        """

        :return:
        """

        try:
            if MESSAGES["KEYS"][0] == 0 and MESSAGES["TLS_VALID_HELLO"][0] == 1:
                self.__client_socket.settimeout(0.5)
                client_key = self.__client_socket.recv(MAX_MSG_LENGTH)

                if not client_key:

                    return

                else:
                    client_key = TLS(client_key)

                    if self.legit_key(client_key):
                        client_key.show()
                        MESSAGES["KEYS"] = 1, client_key
                        return client_key

                    else:
                        return

            else:
                return

        except socket.timeout:
            return

    def legit_key(self, client_keys):
        """

        :param client_keys:
        :return:
        """

        return TLS in client_keys and TLSClientKeyExchange in client_keys

    def server_authentication(self):
        """

        :return:
        """

        if MESSAGES["TLS_VALID_HELLO"][0] == 0 or MESSAGES["KEYS"][0] == 0:
            print("The client is attempting to hide from someone!")

            s_sid = self.create_session_id()

            sec_res = self.new_secure_session(s_sid)
            certificate, key, server_key_ex, private_key = self.certificate_and_key()

            tls_server_hello = sec_res / certificate / server_key_ex
            tls_server_hello = self.prepare_packet_structure(tls_server_hello)

            self.__client_socket.send(bytes(tls_server_hello[TLS]))
            keys = self.handle_responses()

            if not PRIVATE_KEY:
                PRIVATE_KEY.append(private_key)

            return keys, private_key

    def create_session_id(self):
        """
         Create session id
        :return: TLS session id
        """

        s_sid = hashlib.sha256()
        s_sid.update(bytes(N))
        s_sid = s_sid.hexdigest()

        return s_sid

    def new_secure_session(self, s_sid):
        """
         Create the server hello packet
        :param s_sid: TLS Session ID
        :return: TLS server hello packet
        """

        security_layer = (TLS(msg=TLSServerHello(sid=s_sid, cipher=RECOMMENDED_CIPHER,
                                                 ext=(TLS_Ext_SupportedVersion_SH(version=[TLS_MID_VERSION]) /
                                                      TLS_Ext_SignatureAlgorithmsCert(sig_algs=[SIGNATURE_ALGORITHIM]) /
                                                      TLS_Ext_ExtendedMasterSecret() / TLS_Ext_SupportedPointFormat() /
                                                      TLS_Ext_RenegotiationInfo()))))

        security_packet = self.prepare_packet_structure(security_layer)

        return security_packet

    def certificate_and_key(self):
        """
         Create TLS certificate packet and server key exchange packet
        :return: The TLS certificate and server key exchange packet
        """

        original_cert, key, enc_master_c, private_key = self.get_authenticators()
        server_cert = Cert(original_cert[1])

        all_certs = [Cert(original_cert[0]), server_cert, Cert(original_cert[2]), Cert(original_cert[3])]

        sig = key.sign(enc_master_c, GOOD_PAD, THE_SHA_256)  # RSA SIGNATURE on the shared secret
        ec_params = ServerECDHNamedCurveParams(named_curve=SECP, point=enc_master_c)

        d_sign = scapy.layers.tls.keyexchange._TLSSignature(sig_alg=SIGNATURE_ALGORITHIM, sig_val=sig)
        cert_tls = (TLS(msg=TLSCertificate(certs=all_certs)))

        server_key_ex = (TLS(msg=TLSServerKeyExchange(params=ec_params, sig=d_sign)) /
                         TLS(msg=TLSServerHelloDone()))
        ske_msg = server_key_ex

        cert_msg = self.prepare_packet_structure(cert_tls)

        return cert_msg, key, ske_msg, private_key

    def get_authenticators(self):
        """
         Get the certificates and server key
        :return: Certificates, private key, point and private key
        """

        certs, my_key_pem, key = self.retrieve_cert()
        private_key, ec_point = self.generate_public_point()

        return certs, key, ec_point, private_key

    def retrieve_cert(self):
        """
         Create the server certificate
        :return: The public key, the certificate and private key
        """

        certs = []

        for index in range(3, (3 + 1) * 4):
            with open(f'Certificates\\certificate{index}.pem', 'rb') as certificate_first:
                my_cert_pem = certificate_first.read()
                certs.append(my_cert_pem)

        with open(f'Keys\\the_key{3}.pem', 'rb') as key_first:
            my_key_pem = key_first.read()
            key = load_pem_private_key(my_key_pem, b'gfdgdfgdhffdgfdgfdgdf', backend=default_backend())

        return certs, my_key_pem, key

    def generate_public_point(self):
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

    def exchange_server_key(self, keys, private_key, auth):
        """

        :param keys:
        :param private_key:
        :param auth:
        :return:
        """

        if keys or self.legit_key(MESSAGES["KEYS"]):
            print("The exchange has been a success!")
            client_point = keys[TLS][TLSClientKeyExchange][Raw].load
            enc_key = self.create_encryption_key(private_key, client_point)

            server_final = self.create_server_final()  # Change Cipher spec
            self.__client_socket.send(bytes(server_final[TLS]))

            message = b'hello'
            some_data = self.encrypt_data(enc_key, message, auth)

            data_msg = self.create_message(some_data)  # Application data

            self.__client_socket.send(bytes(data_msg[TLS]))
            data = self.deconstruct_data()

            if not data:
                return

            else:
                data_iv, data_c_t, data_tag = data[0], data[1], data[2]

                if self.invalid_data(data_iv, data_c_t, data_tag):
                    return

                else:
                    print(self.decrypt_data(enc_key, auth, data_iv, data_c_t, data_tag))
                    return enc_key

        else:
            print("Error in key exchange")
            self.send_alert()
            return

    def create_encryption_key(self, private_key, client_point):
        """
         Create the server encryption key
        :param client_point: The client point
        :param private_key: The servers private key
        :return: The server encryption key
        """

        client_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_point[1:])
        shared_secret = private_key.exchange(ec.ECDH(), client_key)
        derived_k_f = HKDF(algorithm=THE_SHA_256, length=32, salt=None, info=b'encryption key').derive(shared_secret)

        return derived_k_f

    def create_server_final(self):
        """
         Create the finish message
        :return: The finish message
        """

        server_key = (TLS(msg=TLSChangeCipherSpec()) / TLS(msg=TLSFinished()))
        server_ex = self.prepare_packet_structure(server_key)

        return server_ex

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
         Decrypt the data received by the client
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

        full_data = some_data[0] + some_data[1] + some_data[2]
        data_packet = TLS(msg=TLSApplicationData(data=full_data))
        data_message = self.prepare_packet_structure(data_packet)

        return data_message

    def deconstruct_data(self):
        """
         Dissect the data received from the server
        :return: The data iv, data and tag
        """
        self.__client_socket.settimeout(0.5)

        try:
            data_pack = self.__client_socket.recv(MAX_MSG_LENGTH)
            if not data_pack:
                return

            elif TLSAlert in TLS(data_pack):
                print("THAT IS A SNEAKY CLIENT")
                return 0, 1, 2

            else:
                data_pack = TLS(data_pack)

                data = data_pack[TLS][TLSApplicationData].data
                data_iv = data[:12]

                data_tag = data[len(data) - 16:len(data)]
                data_c_t = data[12:len(data) - 16]

        except IndexError:
            return

        except socket.timeout:
            return

        return data_iv, data_c_t, data_tag

    def invalid_data(self, data_iv, data_c_t, data_tag):
        """

        :param data_iv:
        :param data_c_t:
        :param data_tag:
        :return:
        """

        return data_iv == 0 and data_c_t == 1 and data_tag == 2

    def send_alert(self):
        """

        :return:
        """

        alert = TLS(msg=TLSAlert(level=2, descr=40))
        alert = self.prepare_packet_structure(alert)
        self.__client_socket.send(bytes(alert[TLS]))
