from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
from scapy.layers.tls.all import *
import socket
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import *
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib

SYN = 2
FIN = 1
ACK = 16
THE_USUAL_IP = '0.0.0.0'
MY_IP = conf.route.route('0.0.0.0')[1]
MSS = [("MSS", 1460)]
N = RandShort()  # Key base number
TLS_MID_VERSION = 0x0303
TLS_NEW_VERSION = 0x0304
RECOMMENDED_CIPHER = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val
H_NAME = "bro"
KEY_ENC = serialization.Encoding.X962
FORMAT_PUBLIC = serialization.PublicFormat.UncompressedPoint
THE_PEM = serialization.Encoding.PEM
PRIVATE_OPENSSL = serialization.PrivateFormat.TraditionalOpenSSL
GOOD_PAD = PKCS1v15()
MAX_MSG_LENGTH = 1024
THE_SHA_256 = hashes.SHA256()
SECP = 0x0017
SIGNATURE_ALGORITHIM = 0x0401
THE_LIST = {}


class Server:

    def __init__(self):
        pass

    def first_contact(self):
        """
         Answer a client that is trying to connect to the server
        :return:
        """

        p = sniff(count=1, lfilter=self.filter_udp)
        udp_packet = p[0]
        alt_res = udp_packet.copy()
        alt_res[Raw].load = self.check_if_eligible(alt_res[Ether].src)

        alt_res = self.create_f_response(alt_res)
        alt_res.show()
        sendp(alt_res)

        return udp_packet[UDP].sport,  udp_packet[UDP].dport, alt_res[Raw].load

    def filter_udp(self, packets):
        """
         Check if the packet received is a UDP packet
        :param packets: The packet
        :return: If the packet has UDP in it
        """

        return UDP in packets and Raw in packets and packets[Raw].load == b'Logged'

    def check_if_eligible(self, identifier):

        if identifier in THE_LIST.values():
            return b'Denied'

        else:
            return b'Accept'

    def create_f_response(self, alt_res):
        """
         Create the servers first response
        :param alt_res: The UDP packet
        :return: The UDP response
        """

        new_mac_src = alt_res[Ether].dst
        new_mac_dst = alt_res[Ether].src

        new_src = alt_res[IP].dst
        new_dst = alt_res[IP].src

        new_src_port = alt_res[UDP].dport
        new_dst_port = alt_res[UDP].sport

        alt_res[Ether].src = new_mac_src
        alt_res[Ether].dst = new_mac_dst

        alt_res[IP].src = new_src
        alt_res[IP].dst = new_dst

        alt_res[UDP].sport = new_src_port
        alt_res[UDP].dport = new_dst_port

        alt_res = alt_res.__class__(bytes(alt_res))
        return alt_res

    def first_handshake(self, the_client_socket):
        """
         The tcp handshake
        :param the_client_socket: The client socket
        :return: The ack packet and the server port used the client will use
        """

        first_packet = the_client_socket.recv(MAX_MSG_LENGTH)
        first_data = the_client_socket.recv(MAX_MSG_LENGTH)

        syn_packet = TCP(first_packet)
        syn_data = Raw(first_data)
        syn_packet.show()

        syn_packet = syn_packet / syn_data

        clients_letter = syn_packet[Raw].load

        response = self.create_response(syn_packet)
        the_client_socket.send(bytes(response[TCP]))
        the_client_socket.send(bytes(response[Raw]))

        last_pack = the_client_socket.recv(MAX_MSG_LENGTH)
        last_pack_data = the_client_socket.recv(MAX_MSG_LENGTH)
        ack_packet = TCP(last_pack) / Raw(last_pack_data)

        ack_packet.show()

        clients_dot = ack_packet[Raw].load
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
        packet_auth = packet_auth.__class__(bytes(packet_auth))

        return packet_auth

    def create_session_id(self):
        """
         Create session id
        :return: TLS session id
        """

        s_sid = hashlib.sha256()
        s_sid.update(bytes(N))
        s_sid = s_sid.hexdigest()

        return s_sid

    def secure_handshake(self, client_socket, auth):
        """
         The TLS handshake
        :param client_socket: The client socket
        :param auth: The associate data
        """

        client_hello = client_socket.recv(MAX_MSG_LENGTH)
        s_p = TLS(client_hello)
        s_p.show()

        s_sid = self.create_session_id()

        sec_res = self.new_secure_session(s_sid)
        sec_res.show()

        certificate, key, enc_master_c, server_key_ex, private_key = self.new_certificate()
        client_socket.send(bytes(sec_res[TLS]))  # Server hello
        client_socket.send(bytes(certificate[TLS]))  # Certificate
        client_socket.send(bytes(server_key_ex[TLS]))  # Server key exchange

        client_key_exchange = client_socket.recv(MAX_MSG_LENGTH)
        keys = TLS(client_key_exchange)
        keys.show()

        client_point = keys[TLSClientKeyExchange][Raw].load
        enc_key = self.create_encryption_key(private_key, client_point)
        print("Encryption key\n", enc_key)

        server_final = self.create_server_final()  # Change Cipher spec
        server_final.show()

        client_socket.send(bytes(server_final[TLS]))

        message = b'hello'
        some_data = self.encrypt_data(enc_key, message, auth)
        print(some_data)
        data_msg = self.create_message(some_data)  # Application data

        data_msg.show()
        client_socket.send(bytes(data_msg[TLS]))

        data_iv, data_c_t, data_tag = self.recieve_data(client_socket)

        print(data_iv, data_c_t, data_tag)
        print("==============", "\n", enc_key, "\n", "==============")
        print(self.decrypt_data(enc_key, auth, data_iv, data_c_t, data_tag))

    def new_secure_session(self, s_sid):
        """
         Create the server hello packet
        :param s_sid: TLS Session ID
        :return: TLS server hello packet
        """

        security_layer = (TLS(msg=TLSServerHello(sid=s_sid, cipher=RECOMMENDED_CIPHER,
                                                 ext=TLS_Ext_SupportedVersion_SH(version=[TLS_MID_VERSION]) /
                                                 TLS_Ext_SignatureAlgorithmsCert(sig_algs=[SIGNATURE_ALGORITHIM]))))

        security_packet = security_layer
        security_packet.__class__(bytes(security_packet))
        security_packet.show()

        return security_packet

    def new_certificate(self):
        """
         Create TLS certificate packet and server key exchange packet
        :return: The TLS certificate and server key exchange packet
        """

        original_cert, key, enc_master_c, private_key = self.create_x509()
        server_cert = Cert(original_cert)

        server_cert.show()
        print(key, "\n", server_cert.signatureValue)
        sig = key.sign(enc_master_c, GOOD_PAD, THE_SHA_256)  # RSA SIGNATURE on the shared secret
        ec_params = ServerECDHNamedCurveParams(named_curve=SECP, point=enc_master_c)
        d_sign = scapy.layers.tls.keyexchange._TLSSignature(sig_alg=SIGNATURE_ALGORITHIM, sig_val=sig)

        cert_tls = (TLS(msg=TLSCertificate(certs=server_cert)))

        server_key_ex = (TLS(msg=TLSServerKeyExchange(params=ec_params, sig=d_sign)) /
                         TLS(msg=TLSServerHelloDone()))

        cert_msg = cert_tls
        ske_msg = server_key_ex
        cert_msg.show()
        cert_msg = cert_msg.__class__(bytes(cert_msg))
        cert_msg.show()

        return cert_msg, key, enc_master_c, ske_msg, private_key

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

        print(alt_names)

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
                .sign(key, THE_SHA_256, default_backend(), rsa_padding=GOOD_PAD)
                )

        my_cert_pem = cert.public_bytes(encoding=THE_PEM)
        my_key_pem = key.private_bytes(encoding=THE_PEM, format=PRIVATE_OPENSSL,
                                       encryption_algorithm=serialization
                                       .BestAvailableEncryption(b"dj$bjd&hb2f3v@d55920o@21sf"))
        #  Recreate for storage :D

        with open('certifacte.crt', 'wb') as certificate_first:
            certificate_first.write(my_cert_pem)

        with open('certifacte.pem', 'wb') as certificate_first:
            certificate_first.write(my_cert_pem)

        with open('the_key.pem', 'wb') as key_first:
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

    def create_server_final(self):
        """
         Create the finish message
        :return: The finish message
        """

        with open("certifacte.pem", "rb") as cert_file:
            server_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

        print(len(server_cert.signature))

        server_key = (TLS(msg=TLSChangeCipherSpec()) / TLS(msg=TLSFinished()))
        server_ex = server_key
        server_ex = server_ex.__class__(bytes(server_ex))

        return server_ex

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

        full_data = some_data[0] + some_data[1] + some_data[2]
        data_packet = TLS(msg=TLSApplicationData(data=full_data))
        data_message = data_packet
        data_message = data_message.__class__(bytes(data_message))

        return data_message

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


def main():
    """
    Main function
    """

    while True:
        server = Server()
        client_port, server_port, message = server.first_contact()

        if message == b'Accept':
            the_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            the_server_socket.bind((THE_USUAL_IP, server_port))  # Bind the server IP and Port into a tuple
            the_server_socket.listen()  # Listen to client

            print("Server is up and running")

            connection, client_address = the_server_socket.accept()  # Accept clients request
            print("Client connected")

            client_socket = connection

            acked, auth = server.first_handshake(client_socket)

            server.secure_handshake(client_socket, auth)

            client_socket.close()
            the_server_socket.close()

            break #will be removed later

        elif message == b'Denied':

            print("banned client")
            break

        else:

            print("Error message try again")


if __name__ == '__main__':
    main()
