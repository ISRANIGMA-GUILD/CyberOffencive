import ssl
from security_server import *
from the_server import *
from DatabaseCreator import *
from multiprocessing import Process
import os


class MainRunner:

    def __init__(self, servers_database,  ips_database, login_data_base):

        self.__paths = ["DNS_SERVER", "Servers"]
        self.__passes = {"DNS_SERVER": [], "Servers": []}

        self.__cert_creator = [CertificateCreator("DNS_SERVER"), CertificateCreator("Servers")]
        self.__indexes = {"DNS_SERVER": 19, "Servers": 19}

        self.__security_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.__load_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        self.__secure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.__security_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        self.__load_balance_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.__secure_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        self.__port = 443
        self.__default_ip = '0.0.0.0'

        self.__servers_database = servers_database
        self.__ips_database = ips_database

        self.__login_data_base = login_data_base
        self.__servers_index = 0

        pass

    def run(self):
        """

        """

        for index in range(0, len(self.__paths)):
            self.__passes[self.__paths[index]], self.__indexes[self.__paths[index]] = self.__cert_creator[index].run()

        cert, key = get_certs(self.__passes[self.__paths[0]], self.__paths[0], self.__indexes[self.__paths[0]])

        self.create_security_context()
        self.create_load_context()
        self.create_secure_context()

        DomainProvider(cert, key)

        self.bind_the_constants()

        Security(self.__ips_database, self.__security_socket)

        Server(self.__servers_database, self.__login_data_base, self.__secure_socket, self.__ips_database,
               self.__load_balance_socket, self.__port, self.__passes[self.__paths[1]], self.__indexes[self.__paths[1]])

    def create_security_context(self):
        """

        """

        self.__security_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__servers_index = random.randint(self.__indexes[self.__paths[0]] - 19, self.__indexes[self.__paths[0]])

        self.__security_context.load_cert_chain(certfile=f"DNS_SERVER_Certificates\\certificate{self.__servers_index}.pem",
                                                keyfile=f"DNS_SERVER_Keys\\the_key{self.__servers_index}.key",
                                                password=self.__passes[self.__paths[0]]
                                                         [self.__servers_index - (self.__indexes[self.__paths[0]] - 19)])
        self.__security_context.minimum_version = ssl.TLSVersion.TLSv1_3

        self.__security_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.__security_context.set_ecdh_curve('prime256v1')

        self.__security_socket = self.__security_context.wrap_socket(self.__security_socket,
                                                                     server_hostname="mad.cyberoffensive.org")

    def create_load_context(self):
        """

        """

        self.__secure_context.load_verify_locations(cafile=f"Servers_Certificates\\certificate{0}.pem")

        self.__load_context.check_hostname = True
        self.__load_context.verify_mode = ssl.CERT_REQUIRED

        self.__load_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.__load_context.maximum_version = ssl.TLSVersion.TLSv1_3

        self.__load_context.set_ecdh_curve('prime256v1')
        self.__load_balance_socket = self.__load_context.wrap_socket(self.__load_balance_socket,
                                                                     server_hostname="mad.cyberoffensive.org")

    def create_secure_context(self):
        """

        """

        self.__secure_context.load_verify_locations(cafile=f"DNS_SERVER_Certificates\\certificate{self.__servers_index}.pem")

        self.__secure_context.check_hostname = True
        self.__secure_context.verify_mode = ssl.CERT_REQUIRED

        self.__secure_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.__secure_context.maximum_version = ssl.TLSVersion.TLSv1_3

        self.__secure_context.set_ecdh_curve('prime256v1')
        self.__secure_socket = self.__secure_context.wrap_socket(self.__secure_socket,
                                                                 server_hostname="mad.cyberoffensive.org")

    def bind_the_constants(self):
        """

        """

        while True:
            try:
                self.__security_socket.bind((self.__default_ip, self.__port))
                self.__security_socket.listen(1)

                self.__port += 1
                break

            except OSError:
                self.__port += 1
                pass


def main():

    servers_database = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])
    the_other_database = DatabaseManager("IPs", PARAMETERS["IPs"])

    login_data_base = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])
    runner = MainRunner(servers_database, the_other_database, login_data_base)

    runner.run()


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    main()
