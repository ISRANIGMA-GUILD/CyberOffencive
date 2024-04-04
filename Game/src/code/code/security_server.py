from server_handshake import *
from DatabaseCreator import *


SYN = 2
FIN = 1
ACK = 16
MY_IP = conf.route.route('0.0.0.0')[1]
TLS_M_VERSION = 0x0303
TLS_N_VERSION = 0x0304
RECOMMENDED_CIPHER = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val
MAX_MSG_LENGTH = 1024
SECURITY_PORT = 443
THE_SHA_256 = hashes.SHA256()
THE_BIG_LIST = {"0": "'", "1": ";", "2": "=", "3": '"', "4": "*", "5": "AND", "6": "SELECT", "7": "/", "8": "#",
                "9": "SQL", "10": "FROM", "11": "(", "12": ")", "13": "+", "14": "UNION", "15": "ALL", "16": ">",
                "17": "<", "18": "–dbs", "19": "-D", "20": "-T", "21": "-", "22": ".php", "23": "SLEEP", "24": "@@",
                "25": "CREATE USER", "26": "`", "27": "select", "28": "from", "29": "union", "30": "union",
                "31": "create user", "32": "sleep", "33": "all", "34": "and", "35": "INSERT", "36": "UPDATE",
                "37": "DELETE"}
PARAMETERS = {"IPs": ["IP", "MAC", "Status"]}


class Security:

    def __init__(self, database: DatabaseManager, the_server_socket: socket):
        self.__database = database
        self.__the_server_socket = the_server_socket
        self.__secret_security_key = 0
        self.__secret_message = 0

    def run(self):
        """

        """

        print("secure")
        self.create_server()

    def create_server(self):
        """

        """
        i = 0

        while True:
            try:
                print("Server is up and running")
                connection, service_address = self.__the_server_socket.accept()  # Accept clients request

                print("Client connected")
                service_socket = connection
                if i == 0:
                    self.security_start(service_socket)
                    i += 1

                self.receive_requests(service_socket)

            except ConnectionAbortedError:
                break

            except ConnectionRefusedError:
                break

            except ConnectionResetError:
                break

            except KeyboardInterrupt:
                self.__the_server_socket.close()
                break

            else:
                print("Error message try again")
                i = 0

        print("connect to the main server")

    def security_start(self, service_socket):
        """

        :param service_socket:
        """

        handshake_initializer = ServerHandshake(service_socket)

        while True:
            security_for_server = handshake_initializer.run()

            if not security_for_server:
                pass

            else:
                self.__secret_security_key, self.__secret_message = security_for_server
                handshake_initializer.stop()
                break

    def receive_requests(self, service_socket):
        """

        :param service_socket:
        :return:
        """
        service_socket.settimeout(0.1)
        while True:
            try:
                self.find_ddos_attempt()

                data = service_socket.recv(MAX_MSG_LENGTH)

                if not data:
                    return

            except socket.timeout:
                pass

    def find_ddos_attempt(self):
        """

        """

        requests = sniff(count=5, lfilter=self.filter_tcp, timeout=2)
        ports = [requests[i][TCP].sport for i in range(0, len(requests))]

        for i in range(0, len(ports)):
            if ports.count(ports[i]) > 1:
                print("Ban")
            else:
                print("No error")

    def filter_tcp(self, packets):
        """
         Check if the packet received is a TCP packet
        :param packets: The packet
        :return: If the packet has TCP in it
        """

        return TCP in packets and Raw in packets and (packets[Raw].load == b'Logged' or packets[Raw].load == b'Urgent')


def main():

    database = DatabaseManager("IPs", PARAMETERS["IPs"])
    the_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

    the_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    the_server_socket.bind((MY_IP, SECURITY_PORT))  # Bind the server IP and Port into a tuple

    the_server_socket.listen(1)  # Listen to client
    security = Security(database, the_server_socket)
    security.run()


if __name__ == '__main__':
    main()
