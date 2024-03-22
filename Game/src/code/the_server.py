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
import socket
from DatabaseCreator import *
import os
import threading
import hashlib

SYN = 2
ACK = 16
THE_USUAL_IP = '0.0.0.0'
MY_IP = conf.route.route('0.0.0.0')[1]
MSS = [("MSS", 1460)]
SECURITY_PORT = 443
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
SOCKET_TIMEOUT = 0.5
THE_LIST = {}
KEY = {}
SOCKETS = {}
CLIENTS = {}
CREDENTIALS = {}
MESSAGES = []
LOCATIONS = []
MAX_CLIENT = 5
PARAMETERS = {"PlayerDetails": ['Username', 'Password', 'Cash', 'Status'],
              "NODUP": ['Username', 'Password'], "DUP": ['Cash', 'Status']}


class Server:

    def __init__(self, main_data_base: DatabaseManager, login_data_base: DatabaseManager, secure_socket: socket):
        self.__secure_socket = secure_socket
        self.__main_data_base = main_data_base
        self.__login_data_base = login_data_base

    def run(self):
        """

        """

        self.__secure_socket.connect((MY_IP, SECURITY_PORT))

        accepted_clients, port_list = self.receive_client_connection_request()
        self.create_server_sockets(port_list)

        the_server_sockets = SOCKETS
        threads = []

        lock = threading.Lock()
        print("Server is up and running")

        threads = self.accept_clients(accepted_clients, the_server_sockets, lock, threads)
        self.initiate_handshakes(threads, accepted_clients)

        threads = []

        self.handle_clients(threads, accepted_clients, lock)

    def receive_client_connection_request(self):
        """

        :return:
        """

        while True:
            second, number_of_clients, server_port = self.first_contact()

            if second != 1 and number_of_clients != 0 and server_port != 1:
                messages = [second[index][Raw].load for index in range(0, len(second))]

                print(number_of_clients)
                accepted_clients, port_list = self.check_for_banned(number_of_clients, messages, server_port)

                if accepted_clients > 0:
                    return accepted_clients, port_list

    def first_contact(self):
        """
         Answer a client that is trying to connect to the server
        :return:
        """

        requests, number_of_clients = self.receive_first_connections()
        list_responses = []

        server_port = [requests[index][TCP].dport for index in range(0, len(requests))]
        print(server_port)

        number_of_clients, fixed_requests, fixed_connections = self.search_for_ddos(server_port, requests)

        list_responses = self.analyse_connections(fixed_requests, list_responses)
        if not list_responses:
            return 1, 0, 1

        self.verify_connection_success(number_of_clients, list_responses)

        return list_responses, number_of_clients, fixed_connections

    def receive_first_connections(self):
        """

        :return:
        """

        while True:
            requests = sniff(count=MAX_CLIENT, lfilter=self.filter_tcp, timeout=20)
            number_of_clients = len(requests)

            if number_of_clients > 0 or number_of_clients == MAX_CLIENT:
                break

        return requests, number_of_clients

    def filter_tcp(self, packets):
        """
         Check if the packet received is a TCP packet
        :param packets: The packet
        :return: If the packet has TCP in it
        """

        return TCP in packets and Raw in packets and (packets[Raw].load == b'Logged' or packets[Raw].load == b'Urgent')

    def search_for_ddos(self, server_port, requests):
        """

        :param server_port:
        :param requests:
        :return:
        """

        fixed_connections = [server_port[index] for index in range(0, len(server_port))
                             if server_port.count(server_port[index]) == 1]

        print(fixed_connections)
        fixed_requests = []

        for index in range(0, len(requests)):
            if requests[index][TCP].dport in fixed_connections:
                fixed_requests.append(requests[index])

        number_of_clients = len(fixed_requests)

        return number_of_clients, fixed_requests, fixed_connections

    def analyse_connections(self, requests, list_responses):
        """

        :param requests:
        :param list_responses:
        :return:
        """

        if not requests:
            return

        for index in range(0, len(requests)):
            a_pack = requests[index]
            a_pack[Raw].load = self.check_if_eligible(a_pack[Ether].src)

            a_pack = self.create_f_response(a_pack)
            list_responses.append(a_pack)

        for index in range(0, len(list_responses)):
            sendp(list_responses[index])
            time.sleep(2)

        return list_responses

    def check_if_eligible(self, identifier):
        """

        :param identifier:
        :return:
        """

        if identifier in THE_LIST.values():
            return b'Denied'

        else:
            return b'Accept'

    def create_f_response(self, alt_res):
        """
         Create the servers first response
        :param alt_res: The TCP packet
        :return: The TCP response
        """

        res = alt_res
        new_mac_src = res[Ether].dst
        new_mac_dst = res[Ether].src

        new_src = res[IP].dst
        new_dst = res[IP].src

        new_src_port = res[TCP].dport
        new_dst_port = res[TCP].sport

        res[Ether].src = new_mac_src
        res[Ether].dst = new_mac_dst

        res[IP].src = new_src
        res[IP].dst = new_dst

        res[TCP].sport = new_src_port
        res[TCP].dport = new_dst_port

        res[TCP].flags = SYN + ACK
        res[TCP].ack = res[TCP].seq + 1

        res[TCP].seq = RandShort()
        res = self.prepare_packet_structure(res)

        return res

    def prepare_packet_structure(self, the_packet):
        """

        :param the_packet:
        :return:
        """

        return the_packet.__class__(bytes(the_packet))

    def verify_connection_success(self, number_of_clients, list_responses):
        """

        :param number_of_clients:
        :param list_responses:
        """

        skip = []

        while True:
            requests = sniff(count=number_of_clients, lfilter=self.filter_tcp, timeout=20)

            if len(skip) == number_of_clients or len(requests) == 0:
                break

            for index in range(0, len(requests)):

                if index not in skip:
                    if requests[index] is None:
                        print("Connection success")

                    else:
                        sendp(list_responses[index])
                        skip.append(index)
                        time.sleep(2)

    def check_for_banned(self, number_of_clients, messages, server_port):
        """

        :param number_of_clients:
        :param messages:
        :param server_port:
        """

        for index in range(0, number_of_clients):
            if b'Denied' == messages[index]:
                number_of_clients -= 1
                server_port.pop(index)

        return number_of_clients, server_port

    def create_server_sockets(self, server_port):
        """

        :param server_port:
        """

        print("creating for five clients", server_port)
        for port_number in range(0, len(server_port)):
            the_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            print(server_port[port_number])

            the_server_socket.bind((THE_USUAL_IP, server_port[port_number]))  # Bind the server IP and Port into a tuple
            SOCKETS[str(port_number)] = the_server_socket

    def accept_clients(self, number_of_clients, the_server_socket, lock, threads):
        """

        :param number_of_clients:
        :param the_server_socket:
        :param lock:
        :param threads:
        :return:
        """

        for number in range(0, number_of_clients):
            the_server_socket[str(number)].listen()  # Listen to client
            time.sleep(2)
            connection, client_address = the_server_socket[str(number)].accept()  # Accept clients request

            print(f"Client connected {connection.getpeername()}")
            client_socket = connection

            the_thread = threading.Thread(target=self.create_handshakes, args=(lock, client_socket, number,))
            threads.append(the_thread)
            CLIENTS[str(number)] = client_socket

        return threads

    def initiate_handshakes(self, threads, number_of_clients):
        """

        :param threads:
        :param number_of_clients:
        """

        for number in range(0, number_of_clients):
            threads[number].start()
            print(f"client {number + 1}")

        for number in range(0, number_of_clients):
            threads[number].join()

    def create_handshakes(self, lock, client_socket, number):
        """

        :param lock:
        :param client_socket:
        :param number:
        :return:
        """

        lock.acquire()

        while True:
            acked, auth = self.first_handshake(client_socket, number)

            if auth is None:
                pass

            else:
                enc_key = self.secure_handshake(client_socket, auth, number)
                break

        CLIENTS[str(number)] = client_socket
        KEY[str(number)] = (enc_key, auth)

        lock.release()

    def first_handshake(self, the_client_socket, number):
        """
         The tcp handshake
        :param the_client_socket: The client socket
        :param number:
        :return: The ack packet and the server port used the client will use
        """

        while True:
            first_packet = the_client_socket.recv(MAX_MSG_LENGTH)
            first_data = the_client_socket.recv(MAX_MSG_LENGTH)

            if not first_packet and not first_data:
                print("retrying")
                pass

            else:
                break

        syn_packet = TCP(first_packet)
        syn_data = Raw(first_data)

        syn_packet = syn_packet / syn_data
        clients_letter = syn_packet[Raw].load[0:2]

        response = self.create_response(syn_packet, number)
        the_client_socket.send(bytes(response[TCP]))

        time.sleep(2)
        the_client_socket.send(bytes(response[Raw]))

        last_pack = the_client_socket.recv(MAX_MSG_LENGTH)
        last_pack_data = the_client_socket.recv(MAX_MSG_LENGTH)

        ack_packet = TCP(last_pack) / Raw(last_pack_data)

        clients_dot = ack_packet[Raw].load[0:4]
        auth = clients_letter + clients_dot

        return ack_packet, auth

    def create_response(self, syn_packet, number):
        """
         Server response
        :param syn_packet: The SYN packet
        :param number:
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

        packet_auth[Raw].load = f"hello{number}".encode()
        packet_auth = self.prepare_packet_structure(packet_auth)

        return packet_auth

    def secure_handshake(self, client_socket, auth, number):
        """
         The TLS handshake
        :param client_socket: The client socket
        :param number:
        :param auth: The associate data
        """

        client_hello = client_socket.recv(MAX_MSG_LENGTH)
        t_client_hello = TLS(client_hello)

        keys, private_key = self.server_authentication(t_client_hello, number, client_socket)
        encryption_key = self.exchange_server_key(keys, private_key, client_socket, auth)

        return encryption_key

    def server_authentication(self, t_client_hello, number, client_socket):
        """

        :param t_client_hello:
        :param number:
        :param client_socket:
        :return:
        """

        if self.valid_tls(t_client_hello):
            s_sid = self.create_session_id()
            sec_res = self.new_secure_session(s_sid)

            certificate, key, server_key_ex, private_key = self.certificate_and_key(number)
            client_socket.send(bytes(sec_res[TLS]))  # Server hello

            client_socket.send(bytes(certificate[TLS]))  # Certificate
            time.sleep(2)

            client_socket.send(bytes(server_key_ex[TLS]))  # Server key exchange
            client_key_exchange = client_socket.recv(MAX_MSG_LENGTH)

            keys = TLS(client_key_exchange)

            return keys, private_key

        else:
            print("Client has not used tls properly")
            self.send_alert(client_socket)
            return

    def valid_tls(self, t_client_hello):
        """

        :param t_client_hello:
        :return:
        """

        return (TLSClientHello in t_client_hello and t_client_hello[TLS][TLSClientHello].version == TLS_MID_VERSION
                and t_client_hello[TLS].version == TLS_MID_VERSION)

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

    def certificate_and_key(self, number):
        """
         Create TLS certificate packet and server key exchange packet
        :return: The TLS certificate and server key exchange packet
        """

        original_cert, key, enc_master_c, private_key = self.get_authenticators(number)
        server_cert = Cert(original_cert[1])

        all_certs = [Cert(original_cert[0]), server_cert, Cert(original_cert[2]), Cert(original_cert[3])]
        server_cert.show()

        sig = key.sign(enc_master_c, GOOD_PAD, THE_SHA_256)  # RSA SIGNATURE on the shared secret
        ec_params = ServerECDHNamedCurveParams(named_curve=SECP, point=enc_master_c)

        d_sign = scapy.layers.tls.keyexchange._TLSSignature(sig_alg=SIGNATURE_ALGORITHIM, sig_val=sig)
        cert_tls = (TLS(msg=TLSCertificate(certs=all_certs)))

        server_key_ex = (TLS(msg=TLSServerKeyExchange(params=ec_params, sig=d_sign)) /
                         TLS(msg=TLSServerHelloDone()))
        ske_msg = server_key_ex

        cert_msg = self.prepare_packet_structure(cert_tls)
        cert_msg.show()

        return cert_msg, key, ske_msg, private_key

    def get_authenticators(self, number):
        """
         Get the certificates and server key
        :return: Certificates, private key, point and private key
        """

        certs, my_key_pem, key = self.retrieve_cert(number)
        private_key, ec_point = self.generate_public_point()

        return certs, key, ec_point, private_key

    def retrieve_cert(self, number):
        """
         Create the server certificate
        :return: The public key, the certificate and private key
        """

        certs = []

        for index in range(number, (number + 1) * 4):
            with open(f'Certificates\\certificate{index}.pem', 'rb') as certificate_first:
                my_cert_pem = certificate_first.read()
                certs.append(my_cert_pem)

        with open(f'Keys\\the_key{number}.pem', 'rb') as key_first:
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

    def exchange_server_key(self, keys, private_key, client_socket, auth):
        """

        :param keys:
        :param private_key:
        :param client_socket:
        :param auth:
        :return:
        """

        if self.valid_key_exchange(keys):
            client_point = keys[TLSClientKeyExchange][Raw].load
            enc_key = self.create_encryption_key(private_key, client_point)

            server_final = self.create_server_final()  # Change Cipher spec
            client_socket.send(bytes(server_final[TLS]))

            message = b'hello'
            some_data = self.encrypt_data(enc_key, message, auth)

            data_msg = self.create_message(some_data)  # Application data

            client_socket.send(bytes(data_msg[TLS]))
            data_iv, data_c_t, data_tag = self.deconstruct_data(client_socket)

            if self.invalid_data(data_iv, data_c_t, data_tag):
                return

            else:
                print(self.decrypt_data(enc_key, auth, data_iv, data_c_t, data_tag))
                return enc_key

        else:
            print("Error in key exchange")
            self.send_alert(client_socket)
            return

    def valid_key_exchange(self, keys):
        """

        :param keys:
        :return:
        """

        return TLSClientKeyExchange in keys and keys[TLS].version == TLS_MID_VERSION

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

    def deconstruct_data(self, the_client_socket):
        """
         Dissect the data received from the server
        :param the_client_socket: The client socket
        :return: The data iv, data and tag
        """

        data_pack = the_client_socket.recv(MAX_MSG_LENGTH)
        try:
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

        return data_iv, data_c_t, data_tag

    def invalid_data(self, data_iv, data_c_t, data_tag):
        """

        :param data_iv:
        :param data_c_t:
        :param data_tag:
        :return:
        """

        return data_iv == 0 and data_c_t == 1 and data_tag == 2

    def send_alert(self, client_socket):
        """

        :return:
        """

        alert = TLS(msg=TLSAlert(level=2, descr=40))
        alert = self.prepare_packet_structure(alert)
        client_socket.send(bytes(alert[TLS]))

    def empty_string(self, message):
        """

        :param message:
        :return:
        """

        return message is None or ' ' in message

    def organize_credentials(self, number):
        """

        :param number:
        """

        user, passw = CREDENTIALS[str(number)].decode().split(' ')
        CREDENTIALS[str(number)] = (user, passw)
        print(CREDENTIALS)

    def handle_clients(self, threads, number_of_clients, lock):
        """

        :param threads:
        :param number_of_clients:
        :param lock:
        """

        self.create_credential_list(number_of_clients)
        print(CREDENTIALS)
        while True:
            try:
                login_threads = self.create_credential_threads(number_of_clients, lock)
                response_threads = self.create_responders(threads, number_of_clients, lock)

                self.start_handling(number_of_clients, response_threads, login_threads)

                if self.empty_server():
                    self.__login_data_base.close_conn()
                    self.__main_data_base.close_conn()
                    self.__secure_socket.close()
                    break

                threads = []

            except AttributeError:
                pass

            except ConnectionResetError:
                print("Server will end service")
                break

            except KeyboardInterrupt:
                print("Server will end service")
                break

    def create_credential_list(self, number_of_clients):
        """

        :param number_of_clients:
        """

        for index in range(0, number_of_clients):
            CREDENTIALS[str(index)] = None

    def create_credential_threads(self, number_of_clients, lock):
        """

        :param number_of_clients:
        :param lock:
        :return:
        """

        threads = []

        for number in range(0, number_of_clients):
            the_thread = threading.Thread(target=self.receive_credentials, args=(lock, number))
            threads.append(the_thread)

        return threads

    def create_responders(self, threads, number_of_clients, lock):
        """

        :param threads:
        :param number_of_clients:
        :param lock:
        :return:
        """

        for number in range(0, number_of_clients):
            the_thread = threading.Thread(target=self.respond_to_client, args=(lock, number,))
            threads.append(the_thread)

        return threads

    def start_handling(self, number_of_clients, response_threads, login_threads):
        """

        :param number_of_clients:
        :param response_threads:
        :param login_threads:
        """

        for index in range(0, number_of_clients):
            if CREDENTIALS[str(index)] is not None and CLIENTS[str(index)] is not None:
                response_threads[index].start()

               # if MESSAGES:
                  #  self.send_to_chat()

            else:
                login_threads[index].start()

        for index in range(0, number_of_clients):
            if response_threads[index].is_alive():
                response_threads[index].join()

            elif login_threads[index].is_alive():
                login_threads[index].join()
                self.check_account()

    def receive_credentials(self, lock, number):
        """

        :param lock:
        :param number:
        :return:
        """

        lock.acquire()
        if KEY[str(number)] is not None:
            client_socket = CLIENTS[str(number)]
            enc_key = KEY[str(number)][0]
            auth = KEY[str(number)][1]

            try:
                client_socket.settimeout(SOCKET_TIMEOUT)
                while True:
                    data_iv, data_c_t, data_tag = self.deconstruct_data(client_socket)

                    if self.invalid_data(data_iv, data_c_t, data_tag):
                        lock.release()
                        return

                    else:
                        CREDENTIALS[str(number)] = self.decrypt_data(enc_key, auth, data_iv, data_c_t, data_tag)

                        if CREDENTIALS[str(number)] is not None:
                            self.organize_credentials(number)
                            break

            except TypeError:
                print("Problematic")
                self.eliminate_socket(number)
                lock.release()
                return

            except ConnectionResetError:
                print("Client", number + 1, client_socket.getpeername(), "unexpectedly left")
                self.eliminate_socket(number)
                print("Waited")
                lock.release()
                return

            except AttributeError:
                lock.release()
                return

            except socket.timeout:
                print(CLIENTS[str(number)].getpeername())

                if CREDENTIALS[str(number)] is not None:
                    self.organize_credentials(number)

                lock.release()
                return

        lock.release()

    def respond_to_client(self, lock, index_of_client):
        """

        :param lock:
        :param index_of_client:
        :return:
        """

        lock.acquire()
        if KEY[str(index_of_client)] is not None:
            client_socket = CLIENTS[str(index_of_client)]
            enc_key, auth = KEY[str(index_of_client)]
            client_socket.settimeout(0.1)

            try:
                data = self.deconstruct_data(client_socket)

                if not data:
                    lock.release()
                    return

                else:
                    data_iv, data_c_t, data_tag = data

                    if data_iv == 0 and data_c_t == 1 and data_tag == 2:
                        self.eliminate_socket(index_of_client)
                        lock.release()
                        return

                    decrypted_data = self.decrypt_data(enc_key, auth, data_iv, data_c_t, data_tag)
                    if decrypted_data.decode()[0] == 'L':
                        LOCATIONS.append(decrypted_data)
                        print("Client", index_of_client + 1, "is at", decrypted_data)

                    else:
                        print("Client", index_of_client + 1, "says", decrypted_data)

                    if decrypted_data == b'EXIT':
                        print("Client", index_of_client + 1, client_socket.getpeername(), "has left the server")
                        self.eliminate_socket(index_of_client)

            except TypeError:
                print("Client", index_of_client + 1, client_socket.getpeername(), "unexpectedly left")
                self.eliminate_socket(index_of_client)
                print("Waited")

            except ConnectionResetError:
                print("Client", index_of_client + 1, client_socket.getpeername(), "unexpectedly left")
                self.eliminate_socket(index_of_client)
                print("Waited")

            except socket.timeout:
                pass

            for i in range(0, len(CLIENTS)):
                if i != index_of_client and LOCATIONS and CLIENTS[str(i)] is not None:
                    en = self.encrypt_data(KEY[str(i)][0], LOCATIONS[0], KEY[str(i)][1])
                    CLIENTS[str(i)].send(bytes(self.create_message(en)[TLS]))

            if LOCATIONS:
                LOCATIONS.pop(0)

        lock.release()

    def eliminate_socket(self, number):
        """

        :param number:
        """

        CLIENTS[str(number)].close()
        SOCKETS[str(number)].close()

        CREDENTIALS[str(number)] = None
        SOCKETS[str(number)] = None
        CLIENTS[str(number)] = None

    def empty_server(self):
        """

        :return:
        """

        count_none = [client for client in range(0, len(CLIENTS)) if CLIENTS[str(client)] is None]
        return len(count_none) == len(CLIENTS)

    def check_account(self):
        """

        """
        for client_number in range(0, len(CREDENTIALS)):
            print(CREDENTIALS[str(client_number)])
            if not CREDENTIALS[str(client_number)]:
                pass

            else:
                if not self.account_exists(client_number):
                    print(self.__login_data_base.insert_no_duplicates(values=[CREDENTIALS[str(client_number)][0],
                                                                      CREDENTIALS[str(client_number)][1]],
                                                                      no_duplicate_params=PARAMETERS["NODUP"]))

                else:
                    self.view_status(client_number)

                print(self.__main_data_base.get_content())

    def account_exists(self, client_number):
        """

        :param client_number:
        :return:
        """

        return ([CREDENTIALS[str(client_number)][0], CREDENTIALS[str(client_number)][1]]
                in self.__login_data_base.get_content())

    def view_status(self, client_number):
        """

        :param client_number:
        """

        print(self.__main_data_base.find(return_params=['Status'], input_params=['Username', 'Password'],
                                         values=(CREDENTIALS[str(client_number)][0],
                                                 CREDENTIALS[str(client_number)][1])))

    def send_to_chat(self):
        """

        """

        for client_number in range(0, len(CLIENTS)):
            if CLIENTS[str(client_number)] is not None:
                encrypted_data = self.encrypt_data(KEY[str(client_number)][0], MESSAGES[0], KEY[str(client_number)][1])
                CLIENTS[str(client_number)].send(bytes(self.create_message(encrypted_data)[TLS]))

        MESSAGES.pop(0)


def main():
    """
    Main function
    """
    secure_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    main_data_base = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])
    login_database = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])

    server = Server(main_data_base, login_database, secure_socket)
    server.run()


if __name__ == '__main__':
    main()
