import random

from certificate_creator import *
from serverpassword import *
import ssl

DEFAULT_IP = '0.0.0.0'


class EncryptUniqueServer:

    def __init__(self, path, port, verifiers):
        self.__path = path
        self.__verifiers = verifiers

        self.__security_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.__port = port

    def run(self):
        """

        """
        socket_serv1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        passes = self.__verifiers

        n = random.randint(0, 5)

        self.__security_context.load_cert_chain(certfile=f"{self.__path}_Certificates\\certificate{n}.pem",
                                                keyfile=f"{self.__path}_Keys\\the_key{n}.key",
                                                password=passes[n])

        self.__security_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.__security_context.maximum_version = ssl.TLSVersion.TLSv1_3

        self.__security_context.set_ecdh_curve('prime256v1')

        socket_serv1.setblocking(False)
        socket_serv1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        socket_serv = self.__security_context.wrap_socket(socket_serv1, server_hostname="what.we.know")
        socket_serv1.close()

        socket_serv.bind((DEFAULT_IP, self.__port))
        socket_serv.listen()

        return socket_serv

    def what(self):

        n = random.randint(0, 256)
        print(n)

        n /= 30

        n *= 0

        n += 20

        n += random.randint(0, 384) % 10

        n += 9
