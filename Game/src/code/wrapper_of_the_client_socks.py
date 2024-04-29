import ssl
import socket


class EncryptClient:

    def __init__(self, path, index):

        self.__path = path
        self.__index = index
        self.__secure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        pass

    def run(self):

        return self.create_secure_context()

    def create_secure_context(self):
        """

        """
        socket_serv1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.__secure_context.load_verify_locations(cafile=f"{self.__path}_Certificates/certificate{self.__index}.pem")

        self.__secure_context.check_hostname = True
        self.__secure_context.verify_mode = ssl.CERT_REQUIRED

        self.__secure_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.__secure_context.maximum_version = ssl.TLSVersion.TLSv1_3

        self.__secure_context.set_ecdh_curve('prime256v1')
        socket_client = self.__secure_context.wrap_socket(socket_serv1, server_hostname="mad.cyberoffensive.org")
        socket_serv1.close()

        return socket_client
