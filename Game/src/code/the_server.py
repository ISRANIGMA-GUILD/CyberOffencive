from client_handshake import *
from server_handshake import *
from DatabaseCreator import *
from login import *
import os
import threading
import pickle

SYN = 2
ACK = 16
THE_USUAL_IP = '0.0.0.0'
MY_IP = conf.route.route('0.0.0.0')[1]
MAX_MSG_LENGTH = 1024
LOCAL_HOST = '127.0.0.1'
PARAMETERS = {"PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons'],
              "NODUP": ['Username', 'Password'], "DUP": ['Status', 'Items', 'Weapons'],
              "IPs": ["IP", "MAC", "Status"]}


class Server:

    def __init__(self, main_data_base, login_data_base, secure_socket, ips_data_base, load_balance_socket):
        self.__secure_socket = secure_socket
        self.__load_balance_socket = load_balance_socket

        self.__load_balance_ip = MY_IP  # Will soon be changed according to a mechanism
        self.__load_balance_port = 1800

        self.__main_data_base = main_data_base
        self.__login_data_base = login_data_base

        self.__ips_data_base = ips_data_base
        self.__default_port = 443

        self.__security_private_handshake = ClientHandshake(self.__secure_socket, MY_IP, self.__default_port)
        self.__private_security_key = 0

        self.__private_message = 0
        self.__private_l_security_key = 0

        self.__private_l_message = 0
        self.__number_of_clients = 1

        self.__banned_ips = []
        self.__banned_macs = []

        self.__new_credentials = []
        self.__all_details = []

        self.__credentials = {}
        self.__locations = []

        self.__chat = []
        self.__status = []

        self.__ports = []
        self.__weapon_status = []

        self.__status_frame_index = []
        self.__weapons = []

        self.__hp = []
        self.__enemy_location = []

        self.__items = []
        self.__session_users = []

    def run(self):
        """

        """

        # """:TODO(Are they possible?): Check for session injection vulnerabilities """#
        # """:TODO(almost finished): Check if users are banned """#
        # """:TODO: Transport databases between servers at the end and updating them accordingly """#
        # """:TODO: Check if users cheat(in speed, damage, etc.) """#
        # """:TODO(Almost finished): Block connections from banned users """#
        # """:TODO: Loading screen between menu and login screens """#
        # """:TODO(Work in progress): Merge with load balancer """#
        # """:TODO: Counter attack mechanism (security server) """#
        # """:TODO(almost finished): MAke sure all certificate vital data is randomized and randomize them at start"""#
        # """:TODO(almost finished): Display chat in the game not in the terminal """#
        # """:TODO: Make the whole game abstract from terminal """#
        # """:TODO(almost finished): Try-except on everything """#
        # """:TODO(Work in progress): Receive info about enemy locations, item locations """#
        # """:TODO: Clear ports that are not used"""#
        # """:TODO: Remove clients that quit during the handshake"""#
        # """:TODO(almost finished): Make sure server isn't bogged down due to heavy packs"""#

        info, resource_info, ip_info = self.receive_info()
        list_of_existing_credentials, list_of_existing_resources = self.organize_info(info, resource_info, ip_info)

        print(self.__banned_ips, self.__banned_macs, list_of_existing_resources)

        security_ports = [port for port in range(443, 501)]
        self.connect_to_security(security_ports)
       # self.connect_to_load_socket()
     #   self.first_client_handshake_to_load_balancer()

        self.security_first()
        print("The server will now wait for clients")

        the_lock = threading.Lock()
        login_lock = threading.Lock()

        modification_lock = threading.Lock()
        security_lock = threading.Lock()

        print("Server is up and running")
        self.handle_clients(the_lock, login_lock, modification_lock, security_lock,
                            list_of_existing_credentials, list_of_existing_resources)

    def receive_info(self):
        """

        :return:
        """

        main_cursor = self.__main_data_base.get_cursor()
        main_cursor.execute("SELECT Username, Password FROM PlayerDetails")

        info = main_cursor.fetchall()
        main_resource_cursor = self.__main_data_base.get_cursor()

        main_resource_cursor.execute("SELECT Status, Items, Weapons FROM PlayerDetails")
        resource_info = main_resource_cursor.fetchall()

        main_ip_cursor = self.__ips_data_base.get_cursor()
        main_ip_cursor.execute("SELECT IP, MAC FROM IPs")

        ip_info = main_ip_cursor.fetchall()

        return info, resource_info, ip_info

    def organize_info(self, info, resource_info, ip_info):
        """

        :param info:
        :param resource_info:
        :param ip_info:
        """

        list_of_existing_credentials = [vital_info for vital_info in info]
        list_of_existing_resources = [vital_resources for vital_resources in resource_info]

        self.__banned_ips = [vital_info[0] for vital_info in ip_info]
        self.__banned_macs = [vital_info[1] for vital_info in ip_info]

        return list_of_existing_credentials, list_of_existing_resources

    def connect_to_security(self, security_ports):

        i = 0

        while True:
            try:
                self.__secure_socket.connect((LOCAL_HOST, security_ports[i]))
                self.__default_port = security_ports[i]

                self.__security_private_handshake = ClientHandshake(self.__secure_socket, MY_IP, self.__default_port)
                break

            except ConnectionRefusedError:
                pass

            except ConnectionResetError:
                pass

            except OSError:
                i += 1

    def connect_to_load_socket(self):
        """

        """

        while True:
            try:
                self.__load_balance_socket.connect((MY_IP, 1800))
                break

            except ConnectionRefusedError:
                pass

            except ConnectionResetError:
                pass

            except OSError:
                pass

    def security_first(self):
        """

        """

        while True:
            try:
                security_items = self.__security_private_handshake.run()
                if not security_items:
                    pass

                else:
                    if None not in security_items:
                        self.__private_security_key, self.__private_message = security_items
                        break

                    else:
                        pass

            except ConnectionResetError:
                pass

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
            server_port = requests[TCP].dport
            response = self.analyse_connections(requests)

            if not response:
                return

            else:
                self.verify_connection_success(response)

                return requests, server_port

    def receive_first_connections(self):
        """

        :return:
        """

        requests = sniff(count=1, lfilter=self.filter_tcp, timeout=0.1)
        if not requests:
            return

        elif requests[0][TCP].dport in self.__ports:
            return

        else:
            requests.show()
            self.__ports.append(requests[0])

            return requests[0]

    def filter_tcp(self, packets):
        """
         Check if the packet received is a TCP packet
        :param packets: The packet
        :return: If the packet has TCP in it
        """

        return (TCP in packets and Raw in packets and (packets[Raw].load == b'Logged' or packets[Raw].load == b'Urgent')
                and packets[Ether].src not in self.__banned_macs and packets[IP].src not in self.__banned_ips)

    def analyse_connections(self, requests):
        """

        :param requests:
        :return:
        """

        if not requests:
            return

        else:
            a_pack = requests[0]
            a_pack[Raw].load = self.check_if_eligible(a_pack[Ether].src)

            response = self.create_f_response(a_pack)
            sendp(response)

            return response

    def check_if_eligible(self, identifier):
        """

        :param identifier:
        :return:
        """

        if identifier in self.__banned_macs:
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

    def verify_connection_success(self, response):
        """

        """

        skip = []
        requests = sniff(count=1, lfilter=self.filter_tcp, timeout=0.1)

        if not requests:
            return

        else:
            if 0 not in skip:
                if requests[0] is None:
                    print("Connection success")

                else:
                    sendp(response)
                    skip.append(0)

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

    def create_server_sockets(self, server_port, number):
        """

        :param server_port:
        :param number:
        """
        try:
            print(f"creating for another clients", server_port)
            the_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            print(server_port)

            the_server_socket.bind((THE_USUAL_IP, server_port))  # Bind the server IP and Port into a tuple
            self.__all_details[number]["Socket"] = the_server_socket

        except OSError:
            return

        except TypeError:
            return

        except IndexError:
            return

        return the_server_socket

    def accept_clients(self, the_server_socket, number):
        """

        :param the_server_socket:
        :param number:
        :return:
        """
        try:
            the_server_socket.listen()  # Listen to client
            the_server_socket.settimeout(1)

            connection, client_address = the_server_socket.accept()  # Accept clients request
            print(f"Client connected {connection.getpeername()}")

            client_socket = connection
            self.__all_details[number]["Client"] = client_socket

        except socket.timeout:
            return

        except TypeError:
            return

        except IndexError:
            return

        self.__number_of_clients += 1
        self.__all_details[number]["Timer"] = (time.time(), 0)

    def tls_handshake(self, lock, handshake, number):
        """

        :param handshake:
        :param number:
        :param lock:
        :return:
        """

        with lock:
            start = time.time()
            try:
                if (self.__all_details[number].get("Credentials") is None and self.__all_details[number].get("Client")
                        is not None and self.__all_details[number].get("Keys") is None):

                    enc_key = handshake.run()
                    self.__all_details[number]["Keys"] = enc_key
                    handshake.stop()
                    end = time.time()

                    print(time.strftime("%Hh %Mm %Ss", time.gmtime(end - start)).split(' '))

                else:
                    pass

            except AttributeError:
                end = time.time()

                print(time.strftime("%Hh %Mm %Ss", time.gmtime(end - start)).split(' '))
                pass

            except TypeError:
                end = time.time()

                print(time.strftime("%Hh %Mm %Ss", time.gmtime(end - start)).split(' '))
                return

            except IndexError:
                end = time.time()

                print(time.strftime("%Hh %Mm %Ss", time.gmtime(end - start)).split(' '))
                return

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
        try:
            the_client_socket.settimeout(0.1)
            data_pack = the_client_socket.recv(MAX_MSG_LENGTH)

            if not data_pack:
                return

            elif TLSAlert in TLS(data_pack):
                print("THAT IS A SNEAKY CLIENT")
                return 0, 1, 2

            else:
                try:
                    data_pack = TLS(data_pack)
                    data = data_pack[TLS][TLSApplicationData].data

                    data_iv = data[:12]
                    data_tag = data[len(data) - 16:len(data)]

                    data_c_t = data[12:len(data) - 16]

                    return data_iv, data_c_t, data_tag

                except IndexError:
                    pass
            return

        except struct.error:
            print("dont")
            return

        except socket.timeout:
            return

        except OSError:
            return

        except ConnectionResetError:
            print("reconnect to security")
            return

    def send_alert(self, client_socket):
        """

        :return:
        """

        alert = TLS(msg=TLSAlert(level=2, descr=40))
        alert = self.prepare_packet_structure(alert)
        client_socket.send(bytes(alert[TLS]))

    def handle_clients(self, the_lock, login_lock, security_lock, modification_lock, list_of_existing,
                       list_of_existing_resources):
        """

        :param login_lock:
        :param the_lock:
        :param security_lock:
        :param modification_lock:
        :param list_of_existing:
        :param list_of_existing_resources:
        """

        while True:
            try:
                self.update_credential_list()
                security_thread = self.create_security_threads(security_lock)

                connection_threads = self.create_connection_threads(the_lock)
                tls_handshakes = self.create_tls_handshake_threads(the_lock)

                login_threads = self.create_credential_threads(login_lock, list_of_existing, list_of_existing_resources)
                response_threads = self.create_responders(the_lock)

                details_threads = self.create_detail_threads(the_lock)
                disconnect_threads = self.create_disconnect_threads(modification_lock)

                self.start_handling(security_thread, connection_threads, login_threads, tls_handshakes,
                                    response_threads, disconnect_threads, details_threads)
                self.update_database()

                if self.empty_server():
                    self.update_database()
                    self.__login_data_base.close_conn()
                    self.__main_data_base.close_conn()

                    self.disconnect_from_security()
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

                self.disconnect_from_security()
                self.__ips_data_base.close_conn()

                break

            except KeyboardInterrupt:
                print("Server will end service")
                self.update_database()

                self.__login_data_base.close_conn()
                self.__main_data_base.close_conn()

                self.disconnect_from_security()
                self.__ips_data_base.close_conn()

                break

        print("FINISH")

    def update_credential_list(self):
        """

        """
        if self.__number_of_clients - 1 >= len(self.__all_details) or len(self.__all_details) == 0:
            self.__all_details.append({"Credentials": None, "Keys": None, "Socket": None,
                                       "Client": None, "Timer": None, "Connected": 0, "Port": 0})

        else:
            pass

        self.__credentials[str(self.__number_of_clients - 1)] = None

        if self.__number_of_clients - 1 >= len(self.__locations) or len(self.__locations) == 0:
            self.__locations.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__chat) or len(self.__chat) == 0:
            self.__chat.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__status) or len(self.__status) == 0:
            self.__status.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__items) or len(self.__items) == 0:
            self.__items.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__weapons) or len(self.__weapons) == 0:
            self.__weapons.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__status_frame_index) or len(self.__status_frame_index) == 0:
            self.__status_frame_index.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__session_users) or len(self.__session_users) == 0:
            self.__session_users.append(None)

        else:
            pass

    def create_security_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []
        the_thread = threading.Thread(target=self.handle_security, args=(lock,))
        threads.append(the_thread)

        return threads

    def create_connection_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, len(self.__all_details)):
            the_thread = threading.Thread(target=self.receive_connections, args=(lock, number))
            threads.append(the_thread)

        return threads

    def create_tls_handshake_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, len(self.__all_details)):
            handshake = ServerHandshake(self.__all_details[number].get("Client"))
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

        for number in range(0, len(self.__all_details)):
            the_thread = threading.Thread(target=self.receive_credentials, args=(lock, number, list_of_existing,
                                                                                 list_of_existing_resources))
            threads.append(the_thread)

        return threads

    def create_responders(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, len(self.__all_details)):
            the_thread = threading.Thread(target=self.respond_to_client, args=(lock, number,))
            threads.append(the_thread)

        return threads

    def create_detail_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, len(self.__all_details)):
            the_thread = threading.Thread(target=self.send_updates, args=(lock, number,))
            threads.append(the_thread)

        return threads

    def create_disconnect_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, len(self.__all_details)):
            the_thread = threading.Thread(target=self.eliminate_socket, args=(lock, number,))
            threads.append(the_thread)

        return threads

    def start_handling(self, security_thread, connection_threads, login_threads, tls_handshakes, response_threads,
                       disconnect_threads, detail_threads):
        """

        :param security_thread:
        :param connection_threads:
        :param response_threads:
        :param login_threads:
        :param tls_handshakes:
        :param disconnect_threads:
        :param detail_threads:
        """

        [thread.start() for thread in
         (security_thread + connection_threads + tls_handshakes + login_threads + response_threads + detail_threads +
          disconnect_threads)]

        for thread in (security_thread + connection_threads + tls_handshakes + login_threads + response_threads +
                       detail_threads + disconnect_threads):
            thread.join()

    def handle_security(self, lock):
        """

        :param lock:
        :return:
        """

        with lock:
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

    def first_client_handshake_to_load_balancer(self):
        """

        """

        while True:
            try:
                client_handshake = ClientHandshake(self.__load_balance_socket, self.__load_balance_ip,
                                                   self.__load_balance_port)
                security_items = client_handshake.run()

                if not security_items:
                    pass

                else:
                    self.__private_l_security_key, self.__private_l_message = security_items
                    break

            except ConnectionResetError:
                pass

    def receive_connections(self, lock, number):
        """

        :param lock:
        :param number:
        """

        with lock:
            try:
                if number < len(self.__all_details):
                    if self.__all_details[number].get("Client") is None:
                        port_client = self.receive_client_connection_request()
                        if port_client is None:
                            return

                        else:
                            the_server_socket = self.create_server_sockets(port_client, number)
                            if the_server_socket is None:
                                return

                            else:
                                self.accept_clients(the_server_socket, number)
                                return

            except Exception:
                return

    def receive_credentials(self, lock, number, list_of_existing, list_of_existing_resources):
        """

        :param list_of_existing_resources:
        :param list_of_existing:
        :param number:
        :param lock:
        :return:
        """

        with lock:
            try:
                if (self.__all_details[number].get("Credentials") is None and self.__all_details[number].get("Keys")
                        is not None and self.__all_details[number].get("Client") is not None):

                    loging = Login(self.__all_details[number], list_of_existing, list_of_existing_resources,
                                   self.__credentials, number, self.__new_credentials, self.__number_of_clients)

                    (self.__all_details[number], self.__credentials, list_of_existing, list_of_existing_resources,
                     self.__new_credentials, self.__number_of_clients) = loging.run()

                    if self.__all_details[number].get("Credentials") is not None:
                        self.__session_users[number] = self.__all_details[number].get("Credentials")[0]

            except Exception:
                return

    def respond_to_client(self, lock, index_of_client):
        """

        :param lock:
        :param index_of_client:
        :return:
        """

        with lock:
            try:
                if (self.__all_details[index_of_client].get("Keys") is not None and
                        self.__all_details[index_of_client].get("Credentials") is not None and
                        self.__all_details[index_of_client].get("Client") is not None):

                    client_socket = self.__all_details[index_of_client].get("Client")
                    enc_key, auth = self.__all_details[index_of_client].get("Keys")

                    try:
                        data = self.deconstruct_data(client_socket)

                        if not data:
                            return

                        else:
                            data_iv, data_c_t, data_tag = data

                            if data_iv == 0 and data_c_t == 1 and data_tag == 2:
                                print("hold up bro")
                                self.__all_details[index_of_client]["Connected"] = 1
                                return

                            decrypted_data = self.decrypt_data(enc_key, auth, data_iv, data_c_t, data_tag)

                            if decrypted_data is not None:
                                the_data = pickle.loads(decrypted_data)
                                if type(the_data) is tuple:
                                    print('dup')
                                    return

                                if the_data[0] == 'EXIT':
                                    print("Client", index_of_client + 1, client_socket.getpeername(),
                                          "has left the server")
                                    self.__all_details[index_of_client]["Connected"] = 1

                                    self.__weapons[index_of_client] = the_data[2]
                                    return

                                else:
                                    print("data", the_data)
                                    self.__locations[index_of_client] = the_data[0]

                                    self.__chat[index_of_client] = the_data[1]
                                    print(self.__chat, the_data[1])

                                    self.__status[index_of_client] = the_data[2]
                                    self.__status_frame_index[index_of_client] = the_data[4]

                    except TypeError:
                        print("Client", index_of_client + 1, client_socket.getpeername(), "unexpectedly left")
                        self.__all_details[index_of_client]["Connected"] = 1

                        print("Waited")
                        return

                    except ConnectionAbortedError:
                        print("Client", index_of_client + 1, client_socket.getpeername(), "unexpectedly left")
                        self.__all_details[index_of_client]["Connected"] = 1

                        print("Waited")
                        return

                    except ConnectionResetError:
                        print("Client", index_of_client + 1, client_socket.getpeername(), "unexpectedly left")
                        self.__all_details[index_of_client]["Connected"] = 1

                        print("Waited")
                        return

                    except IndexError:
                        print("Client", index_of_client + 1, client_socket.getpeername(), "unexpectedly left")
                        self.__all_details[index_of_client]["Connected"] = 1

                        print("Waited")
                        return

                    except pickle.PickleError:
                        print("what?")
                        return

                    except socket.timeout:
                        return

            except Exception:
                print("just stop")
                return

    def send_updates(self, lock, number):
        """

        :param lock:
        :param number:
        """

        with lock:
            try:
                if (self.__locations is not None and self.__all_details[number].get("Client") is not None and
                        self.__all_details[number].get("Credentials") is not None and
                        self.__all_details[number].get("Keys") is not None):
                    try:
                        local_locations = self.__locations.copy()
                        local_locations.pop(number)

                        local_messages = self.__chat.copy()
                        local_messages.pop(number)

                        local_statuses = self.__status.copy()
                        local_statuses.pop(number)

                        local_weapons = self.__weapons.copy()
                        local_weapons.pop(number)

                        local_f_indexes = self.__status_frame_index.copy()
                        local_f_indexes.pop(number)

                        list_data = local_locations, local_messages, local_statuses, local_weapons, local_f_indexes
                        byte_data = pickle.dumps(list_data)

                        en = self.encrypt_data(self.__all_details[number].get("Keys")[0], byte_data,
                                               self.__all_details[number].get("Keys")[1])
                        self.__all_details[number].get("Client").send(bytes(self.create_message(en)[TLS]))

                    except ConnectionResetError:
                        pass

                    self.__chat[number] = None

                else:
                    return

            except Exception:
                return

    def eliminate_socket(self, lock, number):
        """

        :param lock:
        :param number:
        """

        with lock:
            try:
                if self.__all_details[number].get("Connected") == 1:

                    self.__all_details[number].get("Client").close()
                    self.__all_details[number].get("Socket").close()

                    self.__all_details.pop(number)
                    self.__credentials[str(number)] = None

                    self.__locations.pop(number)
                    self.__number_of_clients -= 1
                    print(self.__number_of_clients, len(self.__all_details))

            except Exception:
                return

            finally:
                return

    def empty_server(self):
        """

        :return:
        """

        return self.__number_of_clients == 0

    def view_status(self, client_number):
        """

        :param client_number:
        """

        print(self.__main_data_base.find(return_params=['Status'], input_params=['Username', 'Password'],
                                         values=(self.__credentials[str(client_number)][0],
                                                 self.__credentials[str(client_number)][1])))

    def update_database(self):
        """

        """

        for index in range(0, len(self.__new_credentials)):
            self.__login_data_base.insert_no_duplicates(values=[self.__new_credentials[index][0],
                                                                self.__new_credentials[index][1]],
                                                        no_duplicate_params=PARAMETERS["NODUP"])

        print(self.__main_data_base, self.__credentials, self.__weapons,
              len(self.__session_users) == len(self.__weapons))

        for index in range(0, len(self.__session_users) - 1):
            if self.__weapons[index] is not None:
                items = str(self.__weapons[index]["G"]) + ", " + str(self.__weapons[index]["S"])
                print("Ne items", items)

                print(self.__main_data_base.set_values(['Weapons'], [items], ['Username'],
                                                       [self.__session_users[index]]))

    def disconnect_from_security(self):
        """

        """

        try:
            message = "EXIT".encode()
            en = self.encrypt_data(self.__private_security_key, message, self.__private_message)

            self.__secure_socket.send(bytes(self.create_message(en)[TLS]))
            self.__secure_socket.close()

        except ConnectionResetError:
            return

    def get_local_client_details(self):
        """

        :return:
        """

        return self.__main_data_base, self.__login_data_base, self.__ips_data_base


def main():
    """
    Main function
    """

    secure_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    main_data_base = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])

    load_balance_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    login_data_base = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])

    ips_data_base = DatabaseManager("IPs", PARAMETERS["NODUP"])
    server = Server(main_data_base, login_data_base, secure_socket, ips_data_base, load_balance_socket)

    server.run()


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    main()
