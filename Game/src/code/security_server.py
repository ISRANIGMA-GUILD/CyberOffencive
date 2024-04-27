from server_handshake import *
from DatabaseCreator import *
from dnssec_server import *
from certificate_creator import *
from counter_attack import *

SYN = 2
FIN = 1
ACK = 16
MY_IP = conf.route.route('0.0.0.0')[1]
DEFAULT_IP = '0.0.0.0'
TLS_M_VERSION = 0x0303
TLS_N_VERSION = 0x0304
RECOMMENDED_CIPHER = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val
MAX_MSG_LENGTH = 1024
THE_SHA_256 = hashes.SHA256()
THE_BIG_LIST = {"0": "'", "1": ";", "2": "=", "3": '"', "4": "*", "5": "AND", "6": "SELECT", "7": "/", "8": "#",
                "9": "SQL", "10": "FROM", "11": "(", "12": ")", "13": "+", "14": "UNION", "15": "ALL", "16": ">",
                "17": "<", "18": "–dbs", "19": "-D", "20": "-T", "21": "-", "22": ".php", "23": "SLEEP", "24": "@@",
                "25": "CREATE USER", "26": "`", "27": "select", "28": "from", "29": "union", "30": "union",
                "31": "create user", "32": "sleep", "33": "all", "34": "and", "35": "INSERT", "36": "UPDATE",
                "37": "DELETE"}
PARAMETERS = {"IPs": ["IP", "MAC", "Status"], "PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons']}


class Security:

    def __init__(self, database: DatabaseManager, the_server_socket: socket):
        self.__database = database
        self.__the_server_socket = the_server_socket

        self.__secret_security_key = None
        self.__secret_message = None

        self.__cert, self.__key = None, None
        self.__domain_provider = None

        self.__upcoming_bans = []
        self.__currently_banned = []

        self.__service_socket = None
        self.__passes = []

        self.__path = "DNS_SERVER"
        self.__cert_creator = CertificateCreator(self.__path)

        self.__prev_list = []
        self.__counter_attack = None

        self.__max_index = 19

    def run(self):
        """

        """
        main_cursor = self.__database.get_cursor()
        main_cursor.execute("SELECT IP, MAC, Status FROM IPs")

        print("secure")
        info = main_cursor.fetchall()

        list_of_banned_addresses = [vital_info for vital_info in info]
        print(list_of_banned_addresses)

        self.__passes, self.__max_index = self.__cert_creator.run()
        self.__cert, self.__key = get_certs(self.__passes, self.__path, self.__max_index)

        self.__domain_provider = DomainProvider(self.__cert, self.__key)
        self.create_server(list_of_banned_addresses)

    def create_server(self, list_of_banned_addresses):
        """

        """

        while True:
            try:

                if (self.allow_server_connection() and self.__secret_security_key is not None and
                   self.__secret_message is not None):

                    dns_pack = self.__domain_provider.run()

                    self.__domain_provider.handle_client(dns_pack)
                    self.receive_requests(list_of_banned_addresses)

                    if self.__upcoming_bans:
                        for i in range(0, len(self.__upcoming_bans)):
                            self.__database.insert_no_duplicates(values=[self.__upcoming_bans[i][0],
                                                                         self.__upcoming_bans[i][1], 'Banned'],
                                                                 no_duplicate_params=PARAMETERS['IPs'])

            except ConnectionAbortedError:
                break

            except ConnectionRefusedError:
                break

            except ConnectionResetError:
                self.__the_server_socket.close()
                break

            except KeyboardInterrupt:
                self.__the_server_socket.close()
                break

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
                print("Server is up and running")
                connection, service_address = self.__the_server_socket.accept()  # Accept clients request

                print("Client connected")
                service_socket = connection

                self.__service_socket = service_socket
                return True

            except ConnectionAbortedError:
                self.__the_server_socket.close()
                return False

            except ConnectionRefusedError:
                return False

            except ConnectionResetError:
                self.__the_server_socket.close()
                return False

            except KeyboardInterrupt:
                self.__the_server_socket.close()
                return False

        if self.__service_socket is not None and self.__secret_security_key is None and self.__secret_message is None:
            try:
                self.security_start(self.__service_socket)
                if self.__secret_security_key is not None and self.__secret_message is not None:
                    print("yes")
                    return True

            except ConnectionAbortedError:
                self.__the_server_socket.close()
                return False

            except ConnectionRefusedError:
                return False

            except ConnectionResetError:
                self.__the_server_socket.close()
                return False

            except KeyboardInterrupt:
                self.__the_server_socket.close()
                return False

        else:
            return True

    def security_start(self, service_socket):
        """

        :param service_socket:
        """

        if service_socket is not None:
            handshake_initializer = ServerHandshake(service_socket, self.__passes, self.__path, self.__max_index)

            while True:
                try:
                    security_for_server = handshake_initializer.run()

                    if not security_for_server:
                        pass

                    else:
                        if None not in security_for_server:
                            self.__secret_security_key, self.__secret_message = security_for_server
                            handshake_initializer.stop()
                            break

                        else:
                            pass

                except ConnectionResetError:
                    pass

        else:
            return

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
                    banned_addresses = pickle.dumps(banned_addresses)
                    encrypted_message = self.encrypt_data(banned_addresses)

                    banned_message = self.create_message(encrypted_message)
                    self.__service_socket.send(bytes(banned_message[TLS]))

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

    def encrypt_data(self, plaintext):
        """
         Encrypt data before sending it to the client
        :param plaintext: The data which will be encrypted
        :return: The iv, the encrypted data and the encryption tag
        """

        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(self.__secret_security_key), modes.GCM(iv)).encryptor()

        encryptor.authenticate_additional_data(self.__secret_message)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv, ciphertext, encryptor.tag

    def decrypt_data(self, iv, ciphertext, tag):
        """
         Decrypt the data received by the client
        :param iv: The iv
        :param ciphertext: The encrypted data
        :param tag: The encryption tag
        :return: The decrypted data
        """

        decryptor = Cipher(algorithms.AES(self.__secret_security_key), modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(self.__secret_message)

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

    def prepare_packet_structure(self, the_packet):
        """

        :param the_packet:
        :return:
        """

        return the_packet.__class__(bytes(the_packet))

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

            elif TLSAlert in TLS(data_pack):
                print("THAT IS A SNEAKY CLIENT")
                return 0, 1, 2

            else:
                data_pack = TLS(data_pack)

                data = data_pack[TLS][TLSApplicationData].data
                data_iv = data[:12]

                data_tag = data[len(data) - 16:len(data)]
                data_c_t = data[12:len(data) - 16]

        except IndexError:
            return

        except struct.error:
            return

        except socket.timeout:
            return

        return data_iv, data_c_t, data_tag

    def decide(self, data):
        """

        :param data:
        """

        message = self.decrypt_data(data[0], data[1], data[2])

        if message == "EXIT".encode():
            self.__service_socket.close()
            self.__secret_message = None

            self.__service_socket = None
            self.__secret_security_key = None

    def invalid_data(self, data_iv, data_c_t, data_tag):
        """

        :param data_iv:
        :param data_c_t:
        :param data_tag:
        :return:
        """

        return data_iv == 0 and data_c_t == 1 and data_tag == 2

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


def main():
    servers_database = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])
    database = DatabaseManager("IPs", PARAMETERS["IPs"])

    the_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    the_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ports = [i for i in range(443, 501)]
    index = 0

    while True:
        try:
            the_server_socket.bind((DEFAULT_IP, ports[index]))  # Bind the server IP and Port into a tuple
            the_server_socket.listen(1)  # Listen to client

            security = Security(database, the_server_socket)
            security.run()

            servers_database.close_conn()

        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                print("Port is already in use")
                index += 1


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    
    main()
