from client_handshake import *
from server_handshake import *
import socket
from DatabaseCreator import *
import os
import threading
import pickle

SYN = 2
ACK = 16
THE_USUAL_IP = '0.0.0.0'
MY_IP = conf.route.route('0.0.0.0')[1]
SECURITY_PORT = 443
MAX_MSG_LENGTH = 1024
THE_LIST = {}
AUTHORITY_DATA = {}
KEY = {}
SOCKETS = {}
CLIENTS = {}
CREDENTIALS = {}
NEW_CREDENTIALS = []
SUCCESSES = {}
MESSAGES = []
LOCATIONS = {}
CHAT = {}
TIME_LOGIN = {}
MAX_CLIENT = 5
PARAMETERS = {"PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons'],
              "NODUP": ['Username', 'Password'], "DUP": ['Status', 'Items', 'Weapons'],
              "IPs": ["IP", "MAC", "Status"]}


class Server:

    def __init__(self, main_data_base, login_data_base, secure_socket, ips_data_base):
        self.__secure_socket = secure_socket
        self.__main_data_base = main_data_base
        self.__login_data_base = login_data_base
        self.__ips_data_base = ips_data_base
        self.__security_private_handshake = ClientHandshake(self.__secure_socket, MY_IP, SECURITY_PORT)
        self.__private_security_key = 0
        self.__private_message = 0
        self.__number_of_clients = 1
        self.__index_client = 0
        self.__banned_ips = []
        self.__banned_macs = []

    def run(self):
        """

        """
        # """:TODO(Almost finished): Fix port already from the client side (seperate the accept_client and create socket functions) """#
        # """:TODO(If they are possible): Check for session injection vulnerabilities """#
        # """:TODO(almost finished): Check if users are banned """#
        # """:TODO: Transport databases between servers at the end and updating them accordingly """#
        # """:TODO: Check if an emoji is typed """#
        # """:TODO: Check if users cheat(in speed, cash etc.) """#
        # """:TODO(finished?): Connect to docker """#
        # """:TODO(finished?): Return details after login """#
        # """:TODO(Almost finished): Block connections from banned users """#
        # """:TODO: Loading screen between menu and login screens """#
        # """:TODO: Split register and login """#
        # """:TODO(Probably finished): Limit conditions for kick due to manipulated handshakes """#
        # """:TODO: Merge with load balancer """#
        # """:TODO: Counter attack mechanism (security server) """#
        # """:TODO(almost finished): MAke sure all certificate vital data is randomized """#
        # """:TODO(almost finished): Check the ip at the start via getmacbyip any wrongs will cause a ban (CLIENT SIDE)"""#
        # """:TODO(almost finished): Display chat in the game not in the terminal """#
        # """:TODO: Make the whole game abstract from terminal """#
        # """:TODO: Try-except on everything """#

        main_cursor = self.__main_data_base.get_cursor()
        main_cursor.execute("SELECT Username, Password FROM PlayerDetails")

        info = main_cursor.fetchall()
        main_resource_cursor = self.__main_data_base.get_cursor()

        main_resource_cursor.execute("SELECT Status, Items, Weapons FROM PlayerDetails")
        resource_info = main_resource_cursor.fetchall()

        main_ip_cursor = self.__ips_data_base.get_cursor()
        main_ip_cursor.execute("SELECT IP, MAC FROM IPs")

        ip_info = main_ip_cursor.fetchall()

        list_of_existing_credentials = [vital_info for vital_info in info]
        list_of_existing_resources = [vital_resources for vital_resources in resource_info]

        self.__banned_ips = [vital_info[0] for vital_info in ip_info]
        self.__banned_macs = [vital_info[1] for vital_info in ip_info]

        print(self.__banned_ips, self.__banned_macs)

        while True:
            try:
                self.__secure_socket.connect((MY_IP, SECURITY_PORT))
                break

            except ConnectionRefusedError:
                pass

        self.security_first()
        print("The server will now wait for clients")

        lock = threading.Lock()
        print("Server is up and running")

        self.handle_clients(lock, list_of_existing_credentials, list_of_existing_resources)

    def security_first(self):
        """

        """

        while True:
            security_items = self.__security_private_handshake.run()
            if not security_items:
                pass
            else:
                self.__private_security_key, self.__private_message = security_items
                break

    def receive_client_connection_request(self):
        """

        :return:
        """

        important_connections = self.first_contact()
        if not important_connections:
            return

        else:
            second, server_port = important_connections[0], important_connections[1]
            messages = second[Raw].load

            port_client = self.check_for_banned(messages, server_port)

            if not port_client:
                return

            else:
                return port_client

    def first_contact(self):
        """
         Answer a client that is trying to connect to the server
        :return:
        """

        requests = self.receive_first_connections()
        if not requests:
            return

        else:
            list_responses = []
            server_port = requests[TCP].dport
            print(server_port)

            fixed_requests, fixed_connections = self.search_for_ddos(server_port, requests)

            list_responses = self.analyse_connections(fixed_requests, list_responses)
            if not list_responses:
                return

            self.verify_connection_success(list_responses)
            print(fixed_connections)

            return requests, server_port

    def receive_first_connections(self):
        """

        :return:
        """
        requests = sniff(count=1, lfilter=self.filter_tcp, timeout=0.1)
        if not requests:
            return

        else:
            requests.show()
            return requests[0]

    def filter_tcp(self, packets):
        """
         Check if the packet received is a TCP packet
        :param packets: The packet
        :return: If the packet has TCP in it
        """

        return (TCP in packets and Raw in packets and (packets[Raw].load == b'Logged' or packets[Raw].load == b'Urgent')
                and packets[Ether].src not in self.__banned_macs and packets[IP].src not in self.__banned_ips)

    def search_for_ddos(self, server_port, requests):
        """

        :param server_port:
        :param requests:
        :return:
        """

        fixed_connections = server_port

        print(fixed_connections)
        fixed_requests = []

        if fixed_connections:
            fixed_requests.append(requests)

        return fixed_requests, fixed_connections

    def analyse_connections(self, requests, list_responses):
        """

        :param requests:
        :param list_responses:
        :return:
        """

        if not requests:
            return

        for index in range(0, len(requests)):
            a_pack = requests[index]
            a_pack[Raw].load = self.check_if_eligible(a_pack[Ether].src)

            a_pack = self.create_f_response(a_pack)
            list_responses.append(a_pack)

        for index in range(0, len(list_responses)):
            sendp(list_responses[index])

        return list_responses

    def check_if_eligible(self, identifier):
        """

        :param identifier:
        :return:
        """

        if identifier in THE_LIST.values():
            return b'Denied'

        else:
            return b'Accept'

    def create_f_response(self, alt_res):
        """
         Create the servers first response
        :param alt_res: The TCP packet
        :return: The TCP response
        """

        res = alt_res
        new_mac_src = res[Ether].dst
        new_mac_dst = res[Ether].src

        new_src = res[IP].dst
        new_dst = res[IP].src

        new_src_port = res[TCP].dport
        new_dst_port = res[TCP].sport

        res[Ether].src = new_mac_src
        res[Ether].dst = new_mac_dst

        res[IP].src = new_src
        res[IP].dst = new_dst

        res[TCP].sport = new_src_port
        res[TCP].dport = new_dst_port

        res[TCP].flags = SYN + ACK
        res[TCP].ack = res[TCP].seq + 1

        res[TCP].seq = RandShort()
        res = self.prepare_packet_structure(res)

        return res

    def prepare_packet_structure(self, the_packet):
        """

        :param the_packet:
        :return:
        """

        return the_packet.__class__(bytes(the_packet))

    def verify_connection_success(self, list_responses):
        """

        :param list_responses:
        """

        skip = []

        requests = sniff(count=1, lfilter=self.filter_tcp, timeout=0.1)

        if not requests:
            return

        for index in range(0, len(requests)):

            if index not in skip:
                if requests[index] is None:
                    print("Connection success")

                else:
                    sendp(list_responses[index])
                    skip.append(index)

    def check_for_banned(self, messages, server_port):
        """

        :param messages:
        :param server_port:
        """

        if b'Denied' == messages:
            if self.__number_of_clients >= 1:
                self.__number_of_clients -= 1
            server_port = None

        return server_port

    def create_server_sockets(self, server_port):
        """

        :param server_port:
        """
        try:
            print(f"creating for another clients", server_port)
            the_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            print(server_port)

            the_server_socket.bind((THE_USUAL_IP, server_port))  # Bind the server IP and Port into a tuple
            SOCKETS[str(self.__index_client)] = the_server_socket

        except OSError:
            return

        return the_server_socket

    def accept_clients(self, the_server_socket):
        """

        :param the_server_socket:
        :return:
        """
        the_server_socket.listen()  # Listen to client
        the_server_socket.settimeout(1)

        try:
            connection, client_address = the_server_socket.accept()  # Accept clients request
            print(f"Client connected {connection.getpeername()}")

            client_socket = connection
            CLIENTS[str(self.__index_client)] = client_socket

        except socket.timeout:
            return

        self.__number_of_clients += 1
        TIME_LOGIN[str(self.__index_client)] = (time.time(), 0)

    def tls_handshake(self, lock, handshake, number):
        """

        :param handshake:
        :param number:
        :param lock:
        :return:
        """
        lock.acquire()

        if CREDENTIALS[str(number)] is None:
            enc_key = handshake.run()
            KEY[str(number)] = enc_key
            handshake.stop()

        else:
            pass

        lock.release()

    def encrypt_data(self, key, plaintext, associated_data):
        """
         Encrypt data before sending it to the client
        :param key: The server encryption key
        :param plaintext: The data which will be encrypted
        :param associated_data: Data which is associated with yet not encrypted
        :return: The iv, the encrypted data and the encryption tag
        """

        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()

        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv, ciphertext, encryptor.tag

    def decrypt_data(self, key, associated_data, iv, ciphertext, tag):
        """
         Decrypt the data received by the client
        :param key: The server encryption key
        :param associated_data: The data associated with the message
        :param iv: The iv
        :param ciphertext: The encrypted data
        :param tag: The encryption tag
        :return: The decrypted data
        """

        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(associated_data)

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

    def deconstruct_data(self, the_client_socket):
        """
         Dissect the data received from the server
        :param the_client_socket: The client socket
        :return: The data iv, data and tag
        """

        data_pack = the_client_socket.recv(MAX_MSG_LENGTH)

        try:
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

        except socket.timeout:
            print("out of time")
            return

        except IndexError:
            return

        return data_iv, data_c_t, data_tag

    def invalid_data(self, data_iv, data_c_t, data_tag):
        """

        :param data_iv:
        :param data_c_t:
        :param data_tag:
        :return:
        """

        return data_iv == 0 and data_c_t == 1 and data_tag == 2

    def send_alert(self, client_socket):
        """

        :return:
        """

        alert = TLS(msg=TLSAlert(level=2, descr=40))
        alert = self.prepare_packet_structure(alert)
        client_socket.send(bytes(alert[TLS]))

    def empty_string(self, message):
        """

        :param message:
        :return:
        """

        return message is None or ' ' in message

    def organize_credentials(self, number):
        """

        :param number:
        """

        user, passw = CREDENTIALS[str(number)].decode().split(' ')
        CREDENTIALS[str(number)] = (user, passw)
        print(CREDENTIALS)

    def handle_clients(self, lock, list_of_existing, list_of_existing_resources):
        """

        :param list_of_existing:
        :param lock:
        :param list_of_existing_resources:
        """

        while True:
            try:
                self.update_credential_list()
                connection_threads = self.create_connection_threads(lock)

                tls_handshakes = self.create_tls_handshake_threads(lock)
                login_threads = self.create_credential_threads(lock, list_of_existing, list_of_existing_resources)

                response_threads = self.create_responders(lock)
                self.start_handling(connection_threads, response_threads, login_threads, tls_handshakes)

                if self.empty_server():
                    self.update_database()
                    self.__login_data_base.close_conn()
                    self.__main_data_base.close_conn()
                    self.__secure_socket.close()
                    self.__ips_data_base.close_conn()
                    break

            except AttributeError:
                print("wait")
                pass

            except ConnectionResetError:
                print("Server will end service")
                self.update_database()
                self.__login_data_base.close_conn()
                self.__main_data_base.close_conn()
                self.__secure_socket.close()
                self.__ips_data_base.close_conn()
                break

            except KeyboardInterrupt:
                print("Server will end service")
                self.update_database()
                self.__login_data_base.close_conn()
                self.__main_data_base.close_conn()
                self.__secure_socket.close()
                self.__ips_data_base.close_conn()
                break

        print("FINISH")

    def update_credential_list(self):
        """

        """

        CREDENTIALS[str(self.__number_of_clients-1)] = None
        SUCCESSES[str(self.__number_of_clients-1)] = None

        CHAT[str(self.__number_of_clients-1)] = None
        LOCATIONS[str(self.__number_of_clients-1)] = None

        KEY[str(self.__number_of_clients-1)] = None
        AUTHORITY_DATA[str(self.__number_of_clients-1)] = None

        SOCKETS[str(self.__number_of_clients-1)] = None
        CLIENTS[str(self.__number_of_clients-1)] = None
        TIME_LOGIN[str(self.__number_of_clients-1)] = None

    def create_connection_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, self.__number_of_clients):
            the_thread = threading.Thread(target=self.receive_connections, args=(lock,))
            threads.append(the_thread)

        return threads

    def create_tls_handshake_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, self.__number_of_clients):
            handshake = ServerHandshake(CLIENTS[str(number)])
            the_thread = threading.Thread(target=self.tls_handshake, args=(lock, handshake, number))
            threads.append(the_thread)

        return threads

    def create_credential_threads(self, lock, list_of_existing, list_of_existing_resources):
        """

        :param lock:
        :param list_of_existing:
        :param list_of_existing_resources:
        :return:
        """

        threads = []

        for number in range(0, self.__number_of_clients):
            the_thread = threading.Thread(target=self.receive_credentials,
                                          args=(lock, number, list_of_existing, list_of_existing_resources))
            threads.append(the_thread)

        return threads

    def create_responders(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        lock1 = threading.Lock()

        for number in range(0, self.__number_of_clients):
            the_thread = threading.Thread(target=self.respond_to_client, args=(lock1, number,))
            threads.append(the_thread)

        return threads

    def start_handling(self, connection_threads, response_threads, login_threads, tls_handshakes):
        """

        :param connection_threads:
        :param response_threads:
        :param login_threads:
        :param tls_handshakes:
        """

        for index in range(0, self.__number_of_clients):
            if CLIENTS[str(index)] is None:
                self.__index_client = index
                connection_threads[index].start()
                self.handle_security()

            elif CLIENTS[str(index)] is not None and KEY[str(index)] is None:
                tls_handshakes[index].start()

            elif CLIENTS[str(index)] is not None and CREDENTIALS[str(index)] is None:
                login_threads[index].start()

            elif CREDENTIALS[str(index)] is not None and CLIENTS[str(index)] is not None:
                response_threads[index].start()

        for index in range(0, self.__number_of_clients):
            if CLIENTS[str(index)] is None and connection_threads[index].is_alive():
                connection_threads[index].join()

            elif CLIENTS[str(index)] is not None and KEY[str(index)] is None and tls_handshakes[index].is_alive():
                tls_handshakes[index].join()

            elif (CLIENTS[str(index)] is not None and CREDENTIALS[str(index)] is None and
                  login_threads[index].is_alive()):
                login_threads[index].join()

            elif (CREDENTIALS[str(index)] is not None and CLIENTS[str(index)] is not None and
                  response_threads[index].is_alive()):
                response_threads[index].join()

        for i in range(0, len(CLIENTS.keys())):
            if LOCATIONS is not None and CLIENTS[str(i)] is not None and CREDENTIALS[str(i)] is not None \
               and KEY[str(i)] is not None:
                try:
                    local_locations = LOCATIONS.copy()
                    local_locations.pop(str(i))

                    local_messages = CHAT.copy()
                    local_messages.pop(str(i))

                    list_data = local_locations, local_messages
                    byte_data = pickle.dumps(list_data)

                    en = self.encrypt_data(KEY[str(i)][0], byte_data, KEY[str(i)][1])
                    CLIENTS[str(i)].send(bytes(self.create_message(en)[TLS]))

                except ConnectionResetError:
                    pass

        for i in range(0, len(CHAT)):
            CHAT[str(i)] = None

    def handle_security(self):
        """

        :return:
        """

        ban_users = self.security_server_report()
        if not ban_users:
            pass

        else:
            if not self.__banned_ips and not self.__banned_macs:
                self.__banned_ips, self.__banned_macs = ([ban_users[i][0] for i in range(0, len(ban_users))],
                                                         [ban_users[i][1] for i in range(0, len(ban_users))])
            else:
                for i in range(0, len(ban_users)):
                    if ban_users[i][0] not in self.__banned_ips:
                        self.__banned_ips.append(ban_users[i][0])

                    if ban_users[i][1] not in self.__banned_ips:
                        self.__banned_macs.append(ban_users[i][1])

    def security_server_report(self):
        """

        """

        try:
            self.__secure_socket.settimeout(0.1)
            data = self.deconstruct_data(self.__secure_socket)

            if not data:
                return

            else:
                key, auth = self.__private_security_key, self.__private_message
                decrypted_data = self.decrypt_data(key, auth, data[0], data[1], data[2])
                unpacked_data = pickle.loads(decrypted_data)

                return unpacked_data

        except socket.timeout:
            return

    def receive_connections(self, lock):
        """

        :param lock:
        """

        lock.acquire()
        port_client = self.receive_client_connection_request()
        if port_client is None:
            lock.release()
            return

        else:
            the_server_socket = self.create_server_sockets(port_client)
            if the_server_socket is None:
                lock.release()
                return

            else:
                self.accept_clients(the_server_socket)
                lock.release()
                return

    def receive_credentials(self, lock, number, list_of_existing, list_of_existing_resources):
        """

        :param lock:
        :param number:
        :param list_of_existing:
        :param list_of_existing_resources:
        :return:
        """

        lock.acquire()
        if KEY[str(number)] is not None:
            client_socket = CLIENTS[str(number)]
            enc_key = KEY[str(number)][0]

            auth = KEY[str(number)][1]

            try:
                client_socket.settimeout(0.1)
                data = self.deconstruct_data(client_socket)
                if not data:
                    lock.release()
                    return

                else:
                    data_iv, data_c_t, data_tag = data[0], data[1], data[2]

                    if self.invalid_data(data_iv, data_c_t, data_tag):
                        lock.release()
                        return

                    else:
                        CREDENTIALS[str(number)] = self.decrypt_data(enc_key, auth, data_iv, data_c_t, data_tag)
                        self.check_account(number, list_of_existing, list_of_existing_resources)
                        lock.release()
                        return

            except TypeError:
                print("Problematic")
                self.eliminate_socket(number)
                lock.release()
                return

            except ConnectionResetError:
                print("Client", number + 1, client_socket.getpeername(), "unexpectedly left")
                self.eliminate_socket(number)

                print("Waited")
                lock.release()
                return

            except AttributeError:
                lock.release()
                return

            except socket.timeout:
                print(CLIENTS[str(number)].getpeername())
                lock.release()
                return

            except KeyboardInterrupt:
                print("Server will end service")
                lock.release()
                return

        lock.release()
        return

    def respond_to_client(self, lock1, index_of_client):
        """

        :param lock1:
        :param index_of_client:
        :return:
        """

        lock1.acquire()
        if KEY[str(index_of_client)] is not None:
            client_socket = CLIENTS[str(index_of_client)]
            enc_key, auth = KEY[str(index_of_client)]

            client_socket.settimeout(0.1)

            try:
                data = self.deconstruct_data(client_socket)

                if not data:
                    lock1.release()
                    return

                else:
                    data_iv, data_c_t, data_tag = data

                    if data_iv == 0 and data_c_t == 1 and data_tag == 2:
                        self.eliminate_socket(index_of_client)
                        lock1.release()
                        return

                    decrypted_data = self.decrypt_data(enc_key, auth, data_iv, data_c_t, data_tag)

                    if decrypted_data.decode()[0] == 'L':
                        LOCATIONS[str(index_of_client)] = decrypted_data

                    elif decrypted_data.decode()[0:4] == 'CHAT':
                        CHAT[str(index_of_client)] = decrypted_data
                        print(CHAT)

                    if decrypted_data == b'EXIT':
                        print("Client", index_of_client + 1, client_socket.getpeername(), "has left the server")
                        self.eliminate_socket(index_of_client)

            except TypeError:
                print("Client", index_of_client + 1, client_socket.getpeername(), "unexpectedly left")
                self.eliminate_socket(index_of_client)
                print("Waited")

            except ConnectionAbortedError:
                print("Client", index_of_client + 1, client_socket.getpeername(), "unexpectedly left")
                self.eliminate_socket(index_of_client)
                print("Waited")

            except ConnectionResetError:
                print("Client", index_of_client + 1, client_socket.getpeername(), "unexpectedly left")
                self.eliminate_socket(index_of_client)
                print("Waited")

            except socket.timeout:
                pass

        lock1.release()

    def eliminate_socket(self, number):
        """

        :param number:
        """

        CLIENTS[str(number)].close()
        SOCKETS[str(number)].close()

        CREDENTIALS[str(number)] = None

        SOCKETS[str(number)] = None
        CLIENTS[str(number)] = None

    def empty_server(self):
        """

        :return:
        """
        return len(list(CLIENTS.values())) > 1 and len(list(CLIENTS.values())) == list(CLIENTS.values()).count(None)

    def check_account(self, client_number, list_of_existing, list_of_existing_resources):
        """

        :param client_number:
        :param list_of_existing:
        :param list_of_existing_resources:
        """

        if not CREDENTIALS[str(client_number)]:
            pass

        else:

            self.organize_credentials(client_number)
            tuple_of_credentials = CREDENTIALS[str(client_number)]

            count = 0

            for i in range(0, len(CREDENTIALS)):
                if CREDENTIALS[str(client_number)] == CREDENTIALS[str(i)]:
                    count += 1

            if count <= 1:

                list_of_existing_users = [tup[0] for tup in list_of_existing]

                if tuple_of_credentials in list_of_existing:

                    if list_of_existing_resources[client_number][1] != "Banned":
                        print("Successful")
                        success = f"Success {list_of_existing_resources[client_number]}".encode()
                        success_msg = self.encrypt_data(KEY[str(client_number)][0], success, KEY[str(client_number)][1])

                        success_pack = self.create_message(success_msg)
                        CLIENTS[str(client_number)].send(bytes(success_pack[TLS]))

                    else:
                        print("ENTRY DENIED")
                        success = "Failure".encode()

                        success_msg = self.encrypt_data(KEY[str(client_number)][0], success, KEY[str(client_number)][1])
                        success_pack = self.create_message(success_msg)

                        CLIENTS[str(client_number)].send(bytes(success_pack[TLS]))
                        CREDENTIALS[str(client_number)] = None

                else:

                    if (self.username_exists(list_of_existing_users, tuple_of_credentials) and
                       not self.password_exists(list_of_existing, tuple_of_credentials)):

                        print("Wrong username or password")
                        success = "Failure".encode()

                        success_msg = self.encrypt_data(KEY[str(client_number)][0], success, KEY[str(client_number)][1])
                        success_pack = self.create_message(success_msg)

                        CLIENTS[str(client_number)].send(bytes(success_pack[TLS]))
                        CREDENTIALS[str(client_number)] = None

                    else:

                        NEW_CREDENTIALS.append(tuple_of_credentials)
                        print("NEW ACCOUNT YAY :)")

                        success = "Success".encode()
                        success_msg = self.encrypt_data(KEY[str(client_number)][0], success, KEY[str(client_number)][1])

                        success_pack = self.create_message(success_msg)
                        CLIENTS[str(client_number)].send(bytes(success_pack[TLS]))

            else:
                print("Wrong username or password")
                success = "Failure".encode()

                success_msg = self.encrypt_data(KEY[str(client_number)][0], success, KEY[str(client_number)][1])
                success_pack = self.create_message(success_msg)

                CLIENTS[str(client_number)].send(bytes(success_pack[TLS]))
                CREDENTIALS[str(client_number)] = None

    def username_exists(self, list_of_existing_users, tuple_of_credentials):
        """

        :param list_of_existing_users:
        :param tuple_of_credentials:
        :return:
        """

        return tuple_of_credentials[0] in list_of_existing_users

    def password_exists(self, list_of_existing, tuple_of_credentials):
        """

        :param list_of_existing:
        :param tuple_of_credentials:
        :return:
        """

        return tuple_of_credentials[1] in list_of_existing

    def view_status(self, client_number):
        """

        :param client_number:
        """

        print(self.__main_data_base.find(return_params=['Status'], input_params=['Username', 'Password'],
                                         values=(CREDENTIALS[str(client_number)][0],
                                                 CREDENTIALS[str(client_number)][1])))

    def update_database(self):
        """

        """

        for index in range(0, len(NEW_CREDENTIALS)):
            self.__login_data_base.insert_no_duplicates(values=[NEW_CREDENTIALS[index][0], NEW_CREDENTIALS[index][1]],
                                                        no_duplicate_params=PARAMETERS["NODUP"])

    def get_local_client_details(self):

        return self.__main_data_base, self.__login_data_base,


def main():
    """
    Main function
    """
    secure_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    main_data_base = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])
    login_data_base = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])
    ips_data_base = DatabaseManager("IPs", PARAMETERS["NODUP"])

    server = Server(main_data_base, login_data_base, secure_socket, ips_data_base)
    server.run()


if __name__ == '__main__':
    main()
