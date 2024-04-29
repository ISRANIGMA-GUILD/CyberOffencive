import socket
import ssl
import random
import os
from cryptography.x509 import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives.serialization import *
from certificate_creator import *

DEFAULT_IP = '0.0.0.0'


class Encrypt:

    def __init__(self, path):
        self.__path = path
        self.__cert_creator = CertificateCreator(path)
        self.__security_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    def run(self):
        """

        """
        socket_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        passes = self.activate()

        socket_serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        n = random.randint(0, 19)

        self.__security_context.load_cert_chain(certfile=f"{self.__path}_Certificates\\certificate{n}.pem",
                                                keyfile=f"{self.__path}_Keys\\the_key{n}.key",
                                                password=passes[n])

        self.__security_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.__security_context.maximum_version = ssl.TLSVersion.TLSv1_3

        self.__security_context.set_ecdh_curve('prime256v1')
        socket_serv = self.__security_context.wrap_socket(socket_serv, server_hostname="mad.cyberoffensive.org")

        return socket_serv

    def activate(self):

        return self.__cert_creator.run()

    def get_certs(self, passes, path):
        """

        :return:
        """

        n = random.randint(0, 19)
        with open(f'{path}_Certificates/certificate{n}.pem', 'rb') as certificate_first:
            my_cert_pem = load_pem_x509_certificate(certificate_first.read())

        with open(f'{path}_Keys/the_key{n}.pem', 'rb') as certificate_first:
            my_key_pem = load_pem_private_key(certificate_first.read(), password=passes[n].encode())

        return my_cert_pem, my_key_pem, n
