import ssl
from DatabaseCreator import *
from dnssec_server import *
from certificate_creator import *
from counter_attack import *

SYN = 2
FIN = 1
ACK = 16
DEFAULT_IP = '0.0.0.0'
MAX_MSG_LENGTH = 1024
THE_BIG_LIST = {"0": "'", "1": ";", "2": "=", "3": '"', "4": "*", "5": "AND", "6": "SELECT", "7": "/", "8": "#",
                "9": "SQL", "10": "FROM", "11": "(", "12": ")", "13": "+", "14": "UNION", "15": "ALL", "16": ">",
                "17": "<", "18": "–dbs", "19": "-D", "20": "-T", "21": "-", "22": ".php", "23": "SLEEP", "24": "@@",
                "25": "CREATE USER", "26": "`", "27": "select", "28": "from", "29": "union", "30": "union",
                "31": "create user", "32": "sleep", "33": "all", "34": "and", "35": "INSERT", "36": "UPDATE",
                "37": "DELETE"}
PARAMETERS = {"IPs": ["IP", "MAC", "Status"], "PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons']}


class Security:

    def __init__(self):
        self.__servers_database = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])
        self.__database = DatabaseManager("IPs", PARAMETERS["IPs"])

        self.__security_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.__security_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        self.__upcoming_bans = []
        self.__currently_banned = []

        self.__service_socket = None
        self.__prev_list = []

        self.__counter_attack = None
        self.__max_index = 19

        self.__cert_creator = CertificateCreator("DNS_SERVER")

    def run(self):
        """

        """
        main_cursor = self.__database.get_cursor()
        main_cursor.execute("SELECT IP, MAC, Status FROM IPs")

        print("secure")
        info = main_cursor.fetchall()

        list_of_banned_addresses = [vital_info for vital_info in info]
        print(list_of_banned_addresses)

        if self.allow_server_connection():
            self.create_server(list_of_banned_addresses)
            self.__database.close_conn()

    def create_server(self, list_of_banned_addresses):
        """

        """

        try:

            self.receive_requests(list_of_banned_addresses)

            if self.__upcoming_bans:
                for i in range(0, len(self.__upcoming_bans)):
                    self.__database.insert_no_duplicates(values=[self.__upcoming_bans[i][0],
                                                                 self.__upcoming_bans[i][1], 'Banned'],
                                                         no_duplicate_params=PARAMETERS['IPs'])

        except ConnectionAbortedError:
            pass

        except ConnectionRefusedError:
            pass

        except ConnectionResetError:
            self.__security_socket.close()
            pass

        except KeyboardInterrupt:
            self.__security_socket.close()
            pass

        else:
            pass

        print("connect to the main server")
        self.__database.close_conn()

    def allow_server_connection(self):
        """

        :return:
        """

        if self.__service_socket is None:
            try:
                self.create_security_context()
                print("Server is up and running")
                connection, service_address = self.__security_socket.accept()  # Accept clients request

                print("Client connected")
                service_socket = connection

                self.__service_socket = service_socket
                return True

            except ConnectionAbortedError:
                self.__security_socket.close()
                return False

            except ConnectionRefusedError:
                return False

            except ConnectionResetError:
                self.__security_socket.close()
                return False

            except KeyboardInterrupt:
                self.__security_socket.close()
                return False

        else:
            return True

    def create_security_context(self):
        """

        """
        passes = self.activate()
        self.__security_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        n = random.randint(0, 19)
        self.__security_context.load_cert_chain(certfile=f"DNS_SERVER_Certificates\\certificate{n}.pem",
                                                keyfile=f"DNS_SERVER_Keys\\the_key{n}.key",
                                                password=passes[n])
        self.__security_context.minimum_version = ssl.TLSVersion.TLSv1_3

        self.__security_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.__security_context.set_ecdh_curve('prime256v1')

        self.__security_socket = self.__security_context.wrap_socket(self.__security_socket,
                                                                     server_hostname="mad.cyberoffensive.org")

        self.__security_socket.bind((DEFAULT_IP, 443))  # Bind the server IP and Port into a tuple
        #     print("f")
        self.__security_socket.listen(1)  # Listen to client

    def activate(self):

        return self.__cert_creator.run()

    def receive_requests(self, list_of_banned_addresses):
        """

        :return:
        """

        try:
            self.__service_socket.settimeout(4)
            banned_addresses = self.find_ddos_attempt(list_of_banned_addresses)

            if not banned_addresses:
                pass

            else:
                banned_addresses = self.remove_known_users(banned_addresses)

                if not banned_addresses:
                    pass

                else:

                    banned_message = self.create_message(banned_addresses)
                    self.__service_socket.send(banned_message)

                    print("sent")
                    self.__upcoming_bans = pickle.loads(banned_addresses)

            data = self.deconstruct_data()

            if data is None:
                return

            else:
                self.decide(data)

        except socket.timeout:
            pass

    def find_ddos_attempt(self, list_of_banned_addresses):
        """

        """

        requests = sniff(count=500, lfilter=self.filter_tcp, timeout=2)
        ports = [requests[i][TCP].sport for i in range(0, len(requests))]

        banned = []
        for i in range(0, len(ports)):
            if ports.count(ports[i]) >= 500:
                list_banned = [(requests[i][IP].src, requests[i][Ether].src) for i in range(0, len(requests))]
                banned = list_banned

        if not banned:
            print("No error")
            return

        else:
            list_clear = []

            list_repeaters = []
            for i in range(0, len(banned)):
                if (banned[i] not in list_clear and (banned[i][0], banned[i][1], 'Banned') not in
                        list_of_banned_addresses):
                    list_clear.append(banned[i])

                if banned[i] not in list_clear and (banned[i][0], banned[i][1], 'Banned'):
                    list_repeaters.append(banned[i])

            if not list_clear:
                if not list_repeaters:
                    return

                else:
                    self.__counter_attack = DeadlyArrows(list_repeaters)
                    self.__counter_attack.run()
                    return

            else:
                print(list_clear)
                return list_clear

    def filter_tcp(self, packets):
        """
         Check if the packet received is a TCP packet
        :param packets: The packet
        :return: If the packet has TCP in it
        """

        return TCP in packets and Raw in packets and (packets[Raw].load == b'Logged' or packets[Raw].load == b'Urgent')

    def create_message(self, some_data):
        """
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """

        return pickle.dumps(some_data)

    def deconstruct_data(self):
        """
         Dissect the data received from the server
        :return: The data iv, data and tag
        """

        try:
            self.__service_socket.settimeout(0.5)
            data_pack = self.__service_socket.recv(MAX_MSG_LENGTH)

            if not data_pack:
                return

            else:
                data = pickle.loads(data_pack)

        except IndexError:
            return

        except struct.error:
            return

        except socket.timeout:
            return

        return data

    def decide(self, data):
        """

        :param data:
        """

        message = pickle.loads(data)

        if message == ["EXIT".encode()]:
            self.__service_socket.close()
            self.__service_socket = None

    def remove_known_users(self, banned_addresses):
        """

        :param banned_addresses:
        """

        for i in range(0, len(banned_addresses)):
            if ((banned_addresses[i][0], banned_addresses[i][1]) in
                    self.__currently_banned):
                banned_addresses.pop(i)

            else:
                self.__currently_banned.append(banned_addresses[i])

        return banned_addresses
