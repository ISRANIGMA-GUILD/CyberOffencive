from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import *
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
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
THE_SHA_256 = hashes.SHA256()
SECP = 0x0017
SIGNATURE_ALGORITHIM = 0x0401
SOCKET_TIMEOUT = 2
THE_LIST = {}
PREVS = {}
KEY = {}
SOCKETS = {}
CLIENTS = {}
CREDENTIALS = {}
MAX_CLIENT = 5
START_INDEX = 0


class Server:

    def __init__(self):
        pass

    def run(self):
        """

        """

        secure_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        secure_socket.connect((MY_IP, SECURITY_PORT))

        accepted_clients, port_list = self.recieve_client_conenction_request()
        self.create_sockets(port_list)

        the_server_sockets = SOCKETS
        threads = []

        lock = threading.Lock()
        print("Server is up and running")

        threads = self.accept_clients(accepted_clients, the_server_sockets, lock, threads)
        self.initiate_handshakes(threads, accepted_clients)

        self.answer_credentials(accepted_clients, lock, the_server_sockets, secure_socket)
        threads = []

        self.handle_clients(threads, accepted_clients, lock, secure_socket)

    def recieve_client_conenction_request(self):
        """

        :return:
        """

        while True:
            second, number_of_clients, server_port = self.first_contact()
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

        while True:
            requests = sniff(count=MAX_CLIENT, lfilter=self.filter_tcp, timeout=20)
            number_of_clients = len(requests)
            if number_of_clients > 0 or number_of_clients == MAX_CLIENT:
                break

        list_responses = []
        server_port = [requests[index][TCP].dport for index in range(0, len(requests))]
        print(server_port)

        for index in range(0, len(requests)):
            a_pack = requests[index]

            a_pack[Raw].load = self.check_if_eligible(a_pack[Ether].src)

            a_pack = self.create_f_response(a_pack)
            a_pack.show()
            list_responses.append(a_pack)

        for index in range(0, len(list_responses)):
            sendp(list_responses[index])
            time.sleep(2)

        return list_responses, number_of_clients, server_port

    def filter_tcp(self, packets):
        """
         Check if the packet received is a TCP packet
        :param packets: The packet
        :return: If the packet has TCP in it
        """

        return TCP in packets and Raw in packets and packets[Raw].load == b'Logged'

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

    def create_sockets(self, server_port):
        """

        :param server_port:
        """

        print("creating for five clients", server_port)
        for port_number in range(0, len(server_port)):
            the_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            print(server_port[port_number])

            the_server_socket.bind((THE_USUAL_IP, server_port[port_number]))  # Bind the server IP and Port into a tuple
            SOCKETS[str(port_number)] = the_server_socket
            print(SOCKETS)

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
            print(f"client {number}")

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
            print("Retry")
            acked, auth = self.first_handshake(client_socket)

            if auth is None:
                print("Retry")
                pass

            else:
                print("verify", auth)
                enc_key = self.secure_handshake(client_socket, auth)
                break

        CLIENTS[str(number)] = client_socket
        KEY[str(number)] = (enc_key, auth)

        lock.release()

    def first_handshake(self, the_client_socket):
        """
         The tcp handshake
        :param the_client_socket: The client socket
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
        syn_packet.show()

        syn_packet = syn_packet / syn_data
        clients_letter = syn_packet[Raw].load[0:2]

        response = self.create_response(syn_packet)
        the_client_socket.send(bytes(response[TCP]))
        time.sleep(2)
        the_client_socket.send(bytes(response[Raw]))

        last_pack = the_client_socket.recv(MAX_MSG_LENGTH)
        last_pack_data = the_client_socket.recv(MAX_MSG_LENGTH)

        ack_packet = TCP(last_pack) / Raw(last_pack_data)
        ack_packet.show()

        clients_dot = ack_packet[Raw].load[0:4]
        auth = clients_letter + clients_dot

        return ack_packet, auth

    def create_response(self, syn_packet):
        """
         Server response
        :param syn_packet: The SYN packet
        :return packet_auth
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

        packet_auth[Raw].load = b"hello"
        packet_auth = self.prepare_packet_structure(packet_auth)

        return packet_auth

    def secure_handshake(self, client_socket, auth):
        """
         The TLS handshake
        :param client_socket: The client socket
        :param auth: The associate data
        """

        client_hello = client_socket.recv(MAX_MSG_LENGTH)
        t_client_hello = TLS(client_hello)
        t_client_hello.show()

        if self.valid_tls(t_client_hello):
            s_sid = self.create_session_id()

            sec_res = self.new_secure_session(s_sid)
            sec_res.show()

            certificate, key, server_key_ex, private_key = self.new_certificate()
            client_socket.send(bytes(sec_res[TLS]))  # Server hello

            client_socket.send(bytes(certificate[TLS]))  # Certificate
            time.sleep(2)

            client_socket.send(bytes(server_key_ex[TLS]))  # Server key exchange
            client_key_exchange = client_socket.recv(MAX_MSG_LENGTH)

            keys = TLS(client_key_exchange)
            keys.show()

            if self.valid_key_exchange(keys):
                client_point = keys[TLSClientKeyExchange][Raw].load
                enc_key = self.create_encryption_key(private_key, client_point)

                server_final = self.create_server_final()  # Change Cipher spec

                server_final.show()
                client_socket.send(bytes(server_final[TLS]))

                message = b'hello'
                some_data = self.encrypt_data(enc_key, message, auth)

                data_msg = self.create_message(some_data)  # Application data
                data_msg.show()

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
        security_packet.show()

        return security_packet

    def new_certificate(self):
        """
         Create TLS certificate packet and server key exchange packet
        :return: The TLS certificate and server key exchange packet
        """

        original_cert, key, enc_master_c, private_key = self.create_x509()
        print("The type", original_cert)
        server_cert = Cert(original_cert)
        print("The type", server_cert)

        server_cert.show()
        print(key, "\n", server_cert.signatureValue)

        sig = key.sign(enc_master_c, GOOD_PAD, THE_SHA_256)  # RSA SIGNATURE on the shared secret
        ec_params = ServerECDHNamedCurveParams(named_curve=SECP, point=enc_master_c)

        d_sign = scapy.layers.tls.keyexchange._TLSSignature(sig_alg=SIGNATURE_ALGORITHIM, sig_val=sig)
        cert_tls = (TLS(msg=TLSCertificate(certs=server_cert)))

        server_key_ex = (TLS(msg=TLSServerKeyExchange(params=ec_params, sig=d_sign)) /
                         TLS(msg=TLSServerHelloDone()))
        ske_msg = server_key_ex

        cert_msg = self.prepare_packet_structure(cert_tls)
        cert_msg.show()

        return cert_msg, key, ske_msg, private_key

    def create_x509(self):
        """
         Create The X509 certificate and server key
        :return: Certificate, private key, point and private key
        """

        my_cert_pem, my_key_pem, key = self.generate_cert()
        private_key, ec_point = self.generate_public_point()

        return my_cert_pem, key, ec_point, private_key

    def generate_cert(self):
        """
         Create the server certificate
        :return: The public key, the certificate and private key
        """

        # RSA key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        # Create the certificate

        names = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, H_NAME)])

        alt_names = [x509.DNSName(H_NAME), x509.DNSName(MY_IP)]

        basic_constraints = x509.BasicConstraints(ca=True, path_length=0)

        now = datetime.utcnow()

        cert = (x509.CertificateBuilder()
                .subject_name(names)
                .issuer_name(names)
                .public_key(key.public_key())
                .serial_number(1000)
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=365))
                .add_extension(basic_constraints, True)
                .add_extension(x509.SubjectAlternativeName(alt_names), False)
                .sign(key, THE_SHA_256, default_backend(), rsa_padding=PKCS1v15())
                )

        my_cert_pem = cert.public_bytes(encoding=THE_PEM)
        my_key_pem = key.private_bytes(encoding=THE_PEM, format=PRIVATE_OPENSSL,
                                       encryption_algorithm=serialization
                                       .BestAvailableEncryption(b"dj$bjd&hb2f3v@d55920o@21sf"))
        #  Recreate for storage :D

        with open('Certificates\\Certificate_crts\\certifacte.crt', 'wb') as certificate_first:
            certificate_first.write(my_cert_pem)

        with open('Certificates\\certifacte.pem', 'wb') as certificate_first:
            certificate_first.write(my_cert_pem)

        with open('Keys\\the_key.pem', 'wb') as key_first:
            key_first.write(my_key_pem)

        return my_cert_pem, my_key_pem, key

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

    def valid_key_exchange(self, keys):
        """

        :param keys:
        :return:
        """

        return TLSClientKeyExchange in keys and keys[TLS].version == TLS_MID_VERSION

    def create_server_final(self):
        """
         Create the finish message
        :return: The finish message
        """

        with open("Certificates\\certifacte.pem", "rb") as cert_file:
            server_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

        print(len(server_cert.signature))

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

        full_data = some_data[0] + some_data[1] + some_data[2]
        data_packet = TLS(msg=TLSApplicationData(data=full_data))
        data_message = self.prepare_packet_structure(data_packet)

        return data_message

    def answer_credentials(self, number_of_clients, lock, the_server_socket, secure_socket):
        """

        :param number_of_clients:
        :param lock:
        :param the_server_socket:
        :param secure_socket:
        """

        number = 0

        for index in range(0, number_of_clients):
            CREDENTIALS[str(index)] = None

        while True:
            try:
                threads = self.create_credential_threads(number_of_clients, lock)

                for index in range(0, number_of_clients):
                    if CREDENTIALS[str(index)] is None:
                        threads[index].start()

                for index in range(0, number_of_clients):
                    if CREDENTIALS[str(index)] is None:
                        threads[index].join()

                    if KEY[str(index)] == 1:
                        number_of_clients -= 1
                        KEY.pop(str(index))
                        CLIENTS.pop(str(index))
                        the_server_socket[str(index)].close()
                        SOCKETS.pop(str(index))

                        if number_of_clients == 0:
                            secure_socket.close()
                            break

                    number = index

                if len(CREDENTIALS.values()) == number_of_clients:
                    break

            except ConnectionAbortedError:
                the_server_socket[str(number)].close()
                break

            except (socket.timeout, KeyboardInterrupt):

                # If server shuts down due to admin pressing a key (i.e, CTRL + C), shut down the server

                print("Server is shutting down")
                secure_socket.close()
                break

    def create_credential_threads(self, number_of_clients, lock):
        """

        :param number_of_clients:
        :param lock:
        :return:
        """

        threads = []

        for number in range(0, number_of_clients):

            the_thread = threading.Thread(target=self.receive_credentials, args=(lock, number,))
            threads.append(the_thread)

        return threads

    def receive_credentials(self, lock, number):
        """

        :param lock:
        :param number:
        :return:
        """

        lock.acquire()
        client_socket = CLIENTS[str(number)]

        enc_key = KEY[str(number)][0]
        auth = KEY[str(number)][1]

        client_socket.settimeout(SOCKET_TIMEOUT)

        try:
            data_iv, data_c_t, data_tag = self.deconstruct_data(client_socket)

            if self.invalid_data(data_iv, data_c_t, data_tag):
                lock.release()
                return

            else:
                user = self.decrypt_data(enc_key, auth, data_iv, data_c_t, data_tag)
                print(user)

            data_iv2, data_c_t2, data_tag2 = self.deconstruct_data(client_socket)

            if self.invalid_data(data_iv2, data_c_t2, data_tag2):
                lock.release()
                return

            else:
                passw = self.decrypt_data(enc_key, auth, data_iv2, data_c_t2, data_tag2)
                print(passw)
                CREDENTIALS[str(number)] = (user, passw)

        except TypeError:
            print("Retrying")

        except socket.timeout:
            print(CLIENTS[str(number)])
            lock.release()
            return

        lock.release()

    def deconstruct_data(self, the_client_socket):
        """
         Dissect the data received from the server
        :param the_client_socket: The client socket
        :return: The data iv, data and tag
        """

        data_pack = the_client_socket.recv(MAX_MSG_LENGTH)
        if not data_pack:
            return

        elif TLSAlert in TLS(data_pack):
            print("THAT IS A SNEAKY CLIENT")
            return 0, 1, 2

        else:
            data_pack = TLS(data_pack)
            data_pack.show()

            data = data_pack[TLS][TLSApplicationData].data
            data_iv = data[:12]

            data_tag = data[len(data) - 16:len(data)]
            data_c_t = data[12:len(data) - 16]

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

    def handle_clients(self, threads, number_of_clients, lock, secure_socket):
        """

        :param threads:
        :param number_of_clients:
        :param lock:
        :param secure_socket:
        """

        while True:
            try:
                threads = self.create_responders(threads, number_of_clients, lock)

                for index in range(0, number_of_clients):
                    if KEY[str(index)] != 1:
                        threads[index].start()

                for index in range(0, number_of_clients):
                    if KEY[str(index)] != 1:
                        threads[index].join()

                if len(CLIENTS.keys()) == 0:
                    secure_socket.close()
                    break

                threads = []

            except KeyboardInterrupt:
                print("Server will end service")
                break

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

    def respond_to_client(self, lock, index_of_client):
        """

        :param lock:
        :param index_of_client:
        :return:
        """

        lock.acquire()
        client_socket = CLIENTS[str(index_of_client)]

        enc_key, auth = KEY[str(index_of_client)]
        client_socket.settimeout(SOCKET_TIMEOUT)

        try:
            data_iv, data_c_t, data_tag = self.deconstruct_data(client_socket)

            if not data_iv and not data_c_t and not data_tag:
                lock.release()
                return

            if data_iv == 0 and data_c_t == 1 and data_tag == 2:
                client_socket.close()
                KEY[str(index_of_client)] = 1

                print(client_socket)
                lock.release()
                return

            decrypted_data = self.decrypt_data(enc_key, auth, data_iv, data_c_t, data_tag)
            print(decrypted_data)

            if decrypted_data == b'EXIT':
                print("Client", index_of_client, client_socket.getpeername(), "Has exited the server")
                client_socket.close()
                KEY[str(index_of_client)] = 1

                CLIENTS.pop(str(index_of_client))
                the_server_socket = SOCKETS[str(index_of_client)]

                the_server_socket.close()
                SOCKETS.pop(str(index_of_client))

        except TypeError:
            print("Will kick", "Client", index_of_client, client_socket.getpeername())
            client_socket.close()
            KEY[str(index_of_client)] = 1

            CLIENTS.pop(str(index_of_client))
            the_server_socket = SOCKETS[str(index_of_client)]

            the_server_socket.close()
            SOCKETS.pop(str(index_of_client))

        except socket.timeout:
            print("Moving away from", "Client", index_of_client, client_socket.getpeername())
        lock.release()


def main():
    """
    Main function
    """
    server = Server()
    server.run()


if __name__ == '__main__':
    main()
