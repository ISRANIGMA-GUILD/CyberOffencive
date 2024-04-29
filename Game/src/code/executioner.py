import pickle
from security_server import *
from the_server import *
import multiprocessing.process
from cryptography.x509 import *
from cryptography.hazmat.primitives.serialization import *


class MainRunner:

    def __init__(self):

        self.__paths = ["DNS_SERVER", "Servers"]
        self.__passes = {"DNS_SERVER": [], "Servers": []}

        self.__cert_creator = [CertificateCreator("DNS_SERVER"), CertificateCreator("Servers")]
        self.__cert, self.__key = 0, 0

        self.__security_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.__load_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        self.__secure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.__security_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        self.__load_balance_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.__secure_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        self.__port = 443
        self.__default_ip = '0.0.0.0'

        self.__servers_index = 0

    def run(self):
        """
        #Run in multi process and make sure the connect -> servers is seperate from the general communication
        """

        self.__passes[self.__paths[n]] = self.__cert_creator[n].run()

        self.__cert, self.__key = get_certs(self.__passes[self.__paths[n]], self.__paths[n])

        self.create_load_context()
        self.create_secure_context()

        domain = DomainProvider()

        self.bind_the_constants()
#        list_of_d_data = pickle.dumps(data_list)
        list_of_s_data = self.__security_socket

        servern = Server(self.__secure_socket, self.__load_balance_socket, self.__port, self.__passes[self.__paths[1]])

        return domain, list_of_s_data, servern

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


def get_certs(passes, path):
    """

    :return:
    """

    n = random.randint(0, 19)
    with open(f'{path}_Certificates/certificate{n}.pem', 'rb') as certificate_first:
        my_cert_pem = load_pem_x509_certificate(certificate_first.read())

    with open(f'{path}_Keys/the_key{n}.pem', 'rb') as certificate_first:
        my_key_pem = load_pem_private_key(certificate_first.read(), password=passes[n].encode())

    return my_cert_pem, my_key_pem


def create(domain, security, server):
    """

    :param domain:
    :param security:
    :param server:
    :return:
    """
  #  p_p, security_process = multiprocessing.Pipe()
  #  p_p.send(domain)
    domain_process = multiprocessing.Process(target=domain.run())
    security_process = multiprocessing.Process(target=security_starter, args=(security,))
    server_process = multiprocessing.Process(target=server.run)

    return domain_process, security_process, server_process


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    runner = MainRunner()
    data_d_list, data_s_list, server = runner.run()

    while True:
        try:

            d_p, sec_p, s_p = create(data_d_list, data_s_list, server)

            d_p.start()
          #  sec_p.start()
            # print("go f")
          #  s_p.start()
            #
            d_p.join()
            print("yay?")
          #  sec_p.join()
            print("yay!")
          #  s_p.join()

        except KeyboardInterrupt:
            print("lololol")

