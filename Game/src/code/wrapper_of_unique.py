import ssl
import socket

DEFAULT_IP = '0.0.0.0'


class EncryptUniqueServer:

    def __init__(self, path, port, verifiers, number):
        self.__path = path
        self.__verifiers = verifiers

        self.__security_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        self.__port = port
        self.__number = number

    def run(self):
        """

        """

        self.__security_context.load_cert_chain(certfile=f"{self.__path}_Certificates/certificate{self.__number}.pem",
                                                keyfile=f"{self.__path}_Keys/the_key{self.__number}.key",
                                                password=self.__verifiers)

        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        load_balancer_socket = self.__security_context.wrap_socket(temp_socket, server_side=True)
        temp_socket.close()

        load_balancer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        load_balancer_socket.setblocking(False)

        load_balancer_socket.bind((DEFAULT_IP, self.__port))
        load_balancer_socket.listen(1)

        return load_balancer_socket
