from DatabaseCreator import *
from scapy.layers.inet import *
from login import *
from wrapper_of_the_server_socks import *
from wrapper_of_the_client_socks import *
from clientpasswordgen import *
from serverpassword import *
from interesting_numbers import *
import os
import threading
import pickle
import selectors
import errno
from random import *

THE_USUAL_IP = '0.0.0.0'
MY_IP = socket.gethostbyname(socket.gethostname())
MAX_MSG_LENGTH = 16000
LOCAL_HOST = '127.0.0.1'
PARAMETERS = {"PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons'],
              "NODUP": ['Username', 'Password'], "DUP": ['Status', 'Items', 'Weapons'],
              "IPs": ["IP", "MAC", "Status"]}


class Server:

    def __init__(self, main_data_base, login_data_base, ips_data_base, number):
        self.__secure_socket = EncryptClient("Top_Secret", number + 1, "all.we.mightknow").run()
        self.__load_balance_socket = EncryptClient("Secret", number, "load_balancer").run()

        self.__load_balance_ip = self.get_load_balancer_ip()
        print(self.__load_balance_ip)
        self.__load_balance_port = 1800

        self.__main_data_base = main_data_base
        self.__login_data_base = login_data_base

        self.__ips_data_base = ips_data_base
        self.__default_port = 443

        self.__sockets = [EncryptServer("Servers", port).run() for port in [6921, 8843, 8820]]
        self.__number_of_clients = 1

        self.__banned_ips = []
        self.__banned_macs = []

        self.__list_of_banned_users = []
        self.__new_credentials = []

        self.__all_details = []
        self.__credentials = []

        self.__locations = []
        self.__chat = []

        self.__status = []

        self.__weapon_status = []
        self.__weapons = []

        self.__hp = []
        self.__energy = []

        self.__items = []
        self.__session_users = []

        self.__to_send = []
        self.__data_to_send = []

        self.__client_sockets = []
        self.__selector = selectors.DefaultSelector()

        self.__list_of_existing_resources = []
        self.__list_of_existing_existing_credentials = []

        self.__enemy_locations = []
        self.__item_locations = []

        self.__e_possabilities = ["BSS", "BS", "CRS", "CS", "RGS", "RS", "GOB"]
        self.__w_possabilities = ["A", "B", "S", "HPF", "EF", "RHPF", "BEF"]

        self.__server_name = "load_balancer"
        self.__zone = {}

    def run(self):
        """

        """

        # """:TODO(Are they possible?): Check for session injection vulnerabilities """#
        # """:TODO: Add as secret verification between l-> s, s->l, security->s, s->security
        # """:TODO(Work in progress): Use load balancer as the only user of the main database and servers with their local ones"""#
        # """:TODO(Should the server intervene?): Check if users cheat(in speed, damage, etc.) """#
        # """:TODO(almost finished): Loading screen between menu and login screens """#
        # """:TODO(almost finished): Try-except on everything """#
        # """:TODO(almost finished): Make sure server isn't bogged down due to heavy packs"""#
        # """:TODO: Show weapons when attacking"""#
        # """:TODO: Lock the database with a long and strong password"""#
        # """:TODO: Make sure clients move smoothly move between servers"""#
        # """:TODO: Multiprocess security/server"""#
        # """:TODO: Make sure all clients appear )some disappear while still connected)"""#
        # """:TODO: Make sure data is saved even if there is a duplicate password"""#
        # """:TODO: Erase items and enemies from client side to make sure they dont still appear if collected or killed"""#
        # """:TODO(almost finished): Database updates correctly even if server is closed"""#
        # """:TODO(almost finished): Fix attribute error if server closes before clients"""#
        # """:TODO(almost finished): Make sure if items are collected the server knows, enemies update via the server"""#

        info, resource_info, ip_info = self.receive_info()
        self.__list_of_existing_existing_credentials, self.__list_of_existing_resources = self.organize_info(info,
                                                                                                             resource_info,
                                                                                                             ip_info)

        self.set_locations()
        self.set_item_locations()
        self.__list_of_banned_users = [[self.__list_of_existing_existing_credentials[i][0],
                                        self.__list_of_existing_existing_credentials[i][1],
                                        self.__list_of_existing_existing_credentials[i][0]]
                                       for i in range(0, len(self.__list_of_existing_resources))
                                       if self.__list_of_existing_resources[i][0] == "banned"]

        print(self.__banned_ips, self.__banned_macs, self.__list_of_existing_resources, self.__list_of_banned_users)

        print("The server will now wait for clients")
        print("Server is up and running")

       # self.connect_to_security()
        self.connect_to_load_socket()
        self.handle_clients()

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

    def set_locations(self):
        """

        """

        while len(self.__enemy_locations) < 101:
            enemy_is = choice(self.__e_possabilities)
            self.__enemy_locations.append((enemy_is, (randint(1000, 3000), randint(1000, 3000))))

    def set_item_locations(self):
        """

        """

        while len(self.__item_locations) < 20:
            enemy_is = choice(self.__w_possabilities)
            self.__item_locations.append((enemy_is, (randint(1000, 3000), randint(1000, 3000))))

    def connect_to_security(self):
        """

        """

        while True:
            try:
                self.__secure_socket.connect((LOCAL_HOST, 443))
                print("succ")

                break

            except ConnectionRefusedError as e:
                print("what", e)

            except ConnectionResetError as e:
                print("huh", e)

            except socket.error as e:
                if e.errno == errno.EADDRINUSE:
                    print("Port is already in use")

    def connect_to_load_socket(self):
        """

        """

        while True:
            try:
                self.__load_balance_socket.connect((self.__load_balance_ip, 1800))
                print("SSL connection established with Load Balancer.")

                # Receive configuration data from the load balancer
                data = self.__load_balance_socket.recv(1024)  # Adjust buffer size based on expected data
                configuration = pickle.loads(data)

                self.__server_name = configuration['server_name']
                self.__zone = configuration['zone']
                
                print(f"Received configuration: Server Name - {self.__server_name}, Zone - {self.__zone}")
                break

            except ConnectionRefusedError:
                pass

            except ConnectionResetError:
                pass

            except OSError:
                pass

        print("out")

    def send_message_to_load_balancer(self, message):
        """
        Send messages to the Load Balancer.
        :param message:
        """
        try:
            self.__load_balance_socket.send(pickle.dumps(message))
            print(f"Message sent to Load Balancer: {message}")
        except Exception as e:
            print(f"Failed to send message: {e}")

    def handle_client_location(self, client_location):
        """
        Check client location and notify load balancer if out of zone.
        :param client_location:
        """

        key = list(self.__zone.keys())[0]
        x, y = client_location

        min_x, max_x, min_y, max_y = (self.__zone.get(key)['min_x'], self.__zone.get(key)['max_x'],
                                      self.__zone.get(key)['min_y'], self.__zone.get(key)['max_y'])

        if not (min_x <= x <= max_x and min_y <= y <= max_y):
            print(f"Client location {client_location} out of assigned zone.")
            self.send_message_to_load_balancer({'type': 'out_of_zone', 'location': client_location, 'server':
                                                self.__server_name, 'client_data': self.get_local_client_details})

        else:
            print("Client location within assigned zone.")

    def complete_connection(self):
        """

        :return:
        """

        try:
            self.__load_balance_socket.getsockname()  # Check if connection is established

        except socket.error:
            print("Socket not yet connected, retrying...")
            return

        print("Successfully connected to the load balancer.")
        self.receive_configiration_from_load_balancer()

    def receive_configiration_from_load_balancer(self):
        """

        """

        try:
            self.__load_balance_socket.settimeout(0.1)
            data = self.__load_balance_socket.recv(1024)
            if data:
                configuration = pickle.loads(data)
                self.__server_name = configuration['server_name']
                self.__zone = configuration['zone']
                print(f"Received configuration: Server Name - {self.__server_name}, Zone - {self.__zone}")
            else:
                print("Load balancer closed the connection.")
                self.__load_balance_socket.close()

        except ssl.SSLError as e:
            print(f"SSL error: {e}")

        except Exception as e:
            print(f"Error: {e}")

    def receive_data_from_load_balancer(self):
        """

        """

        try:
            self.__load_balance_socket.settimeout(0.1)
            data = self.__load_balance_socket.recv(1024)

            if data:
                new_client_info = pickle.loads(data)
                self.add_new_client(new_client_info)

        except Exception as e:
            print("Failed to receive data from load balancer:", e)
            self.__load_balance_socket.close()

    def add_new_client(self, client_info):
        """

        :param client_info:
        """

        username, client_details = client_info['username'], client_info['details']
        self.__session_users.append(username)

        self.__all_details.append(client_details)
        print(f"Added new client {username} with details {client_details}")

    def check_for_banned(self, client_address, number):
        """

        :param client_address:
        :param number:
        """

        print(client_address)
        if client_address[0] in self.__banned_ips or getmacbyip(client_address[0]) in self.__banned_macs:
            self.__all_details[number]["Connected"] = 1

        else:
            print("success")

    def create_server_sockets(self):
        """

        """

        try:
            if len(self.__sockets) < 3:
                port = random.choice([6921, 8843, 8820])
                sockets = EncryptServer("Servers", port).run()

                print(f"creating for clients")
                self.__sockets.append(sockets)

        except OSError as e:
            print(e)
            return

        except TypeError as e:
            print(e)
            return

        except IndexError as e:
            print(e)
            return

    def create_message(self, some_data):
        """
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """

        full_data = pickle.dumps(some_data)

        return full_data

    def handle_clients(self):
        """

        """
        self.__selector.register(self.__sockets[0], selectors.EVENT_READ, self.accept_client)
        self.__selector.register(self.__sockets[1], selectors.EVENT_READ, self.accept_client)
        self.__selector.register(self.__sockets[2], selectors.EVENT_READ, self.accept_client)

       # self.__selector.register(self.__load_balance_socket, selectors.EVENT_READ, self.receive_data_from_load_balancer)
        while True:
            try:

                self.new_handling()

            #       except AttributeError:
            #       print("wait huh")
            #      pass

            except ConnectionResetError as e:
                print("Server will end service")
                print(e)

                self.update_database()
                self.__login_data_base.close_conn()

                self.__main_data_base.close_conn()
               # self.disconnect_from_security()

                self.__ips_data_base.close_conn()
                break

            except KeyboardInterrupt as e:
                print("Server will end service")
                print(e)

                self.update_database()
                self.kick_all()

                self.__login_data_base.close_conn()
                self.__main_data_base.close_conn()
          #      self.disconnect_from_security()

                self.__ips_data_base.close_conn()
                break

        print("FINISH")

    def update_credential_list(self):
        """

        """

        if self.__number_of_clients - 1 >= len(self.__all_details) or len(self.__all_details) == 0:
            self.__all_details.append({"Credentials": None, "Sockets": None, "Client": None, "Timer": None,
                                       "Connected": 0})

        if self.__number_of_clients - 1 >= len(self.__credentials) or len(self.__credentials) == 0:
            self.__credentials.append(None)

        if self.__number_of_clients - 1 >= len(self.__locations) or len(self.__locations) == 0:
            self.__locations.append(None)

        if self.__number_of_clients - 1 >= len(self.__chat) or len(self.__chat) == 0:
            self.__chat.append(None)

        if self.__number_of_clients - 1 >= len(self.__status) or len(self.__status) == 0:
            self.__status.append(None)

        if self.__number_of_clients - 1 >= len(self.__items) or len(self.__items) == 0:
            self.__items.append(None)

        if self.__number_of_clients - 1 >= len(self.__weapons) or len(self.__weapons) == 0:
            self.__weapons.append(None)

        if self.__number_of_clients - 1 >= len(self.__session_users) or len(self.__session_users) == 0:
            self.__session_users.append(None)

    def create_security_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []
        the_thread = threading.Thread(target=self.handle_security, args=(lock,))
        threads.append(the_thread)

        return threads

    def new_handling(self):
        """

        """
        events = self.__selector.select(0)

        for key, mask in events:

            self.update_credential_list()
            self.update_database()
            self.update_items()
            self.receive_data_from_load_balancer()

            callback = key.data
            callback(key.fileobj, mask)

    def accept_client(self, current_socket, mask):
        """

        :param current_socket:
        :param mask:
        """

        target = list(filter(lambda person: person["Sockets"] is None and person["Credentials"] is None,
                             self.__all_details))[0]
        index = self.__all_details.index(target)

        # print("pre index", index)
        passw = GetPassword(128).run()

        my_pass = Verifier(256).run()
        connection, client_address = current_socket.accept()

        try:
            connection.settimeout(1)
            their_pass = pickle.loads(connection.recv(MAX_MSG_LENGTH))

            if their_pass[0] != passw:
                print("shut up")
                connection.close()
                return

        except socket.timeout:
            print("out")
            connection.close()
            return

        except pickle.UnpicklingError as e:
            print("BAN!", e)
            connection.close()
            return

        try:
            connection.send(pickle.dumps([my_pass]))
            print("New client joined!", client_address)

            self.__to_send.append((current_socket, "yay"))
            self.check_for_banned(client_address, index)

            self.__client_sockets.append(connection)

            self.__all_details[index]["Client"] = connection
            self.__all_details[index]["Sockets"] = current_socket

            self.__number_of_clients += 1
            self.print_client_sockets()

            connection.setblocking(False)
            self.__selector.register(connection, selectors.EVENT_READ, self.receive_login)

        except ConnectionResetError as e:
            print(e)
            connection.close()

    def receive_login(self, current_socket, mask):
        """

        :param current_socket:
        :param mask:
        """

        target = list(filter(lambda person: person["Client"] == current_socket and person["Credentials"] is None,
                             self.__all_details))[0]
        index = self.__all_details.index(target)

        try:
            current_socket.settimeout(0.5)
            data = pickle.loads(current_socket.recv(MAX_MSG_LENGTH))

            if "EXIT" in data[0]:
                self.__all_details[index]["Connected"] = 1
                self.__weapons[index] = data[2]
                self.update_database()

                self.print_client_sockets()
                self.eliminate_socket(index)

            else:
                if type(data) is tuple:
                    loging = Login(self.__all_details[index], self.__list_of_existing_existing_credentials,
                                   self.__list_of_existing_resources, self.__credentials, index,
                                   self.__new_credentials, self.__number_of_clients,
                                   self.__list_of_banned_users, data)

                    (self.__all_details[index], self.__credentials, list_of_existing, list_of_existing_resources,
                     self.__new_credentials, self.__number_of_clients) = loging.run()
                    self.__to_send.append((current_socket, data))

                    if self.__all_details[index].get("Credentials") is not None:
                        self.__session_users[index] = self.__all_details[index].get("Credentials")[0]
                        self.__selector.modify(current_socket, selectors.EVENT_READ, self.update_clients)

        except socket.timeout:
            pass

        except ssl.SSLEOFError as e:
            print("Connection closed", e)
            self.__all_details[index]["Connected"] = 1

            self.print_client_sockets()
            self.eliminate_socket(index)

        except EOFError as e:
            print("Connection closed", e)
            self.__all_details[index]["Connected"] = 1

            self.print_client_sockets()
            self.eliminate_socket(index)

    def update_clients(self, current_socket, mask):
        """

        :param current_socket:
        :param mask:
        """

        target = list(filter(lambda person: person["Client"] == current_socket and person["Credentials"] is not None,
                             self.__all_details))[0]
        index = self.__all_details.index(target)

        try:
            current_socket.settimeout(0.01)
            data = pickle.loads(current_socket.recv(MAX_MSG_LENGTH))

            # print(data)
            if "EXIT" in data[0]:
                print("Connection closed", data)
                self.__all_details[index]["Connected"] = 1

                self.eliminate_socket(index)
                self.print_client_sockets()

                self.__weapons[index] = data[2]
                self.update_database()

            elif len(self.__credentials) <= len(self.__session_users) and type(data) is not tuple:
                nearby_sprites = self.nearby_them(index)

                if nearby_sprites:
                    for message in nearby_sprites:
                        current_socket.send(pickle.dumps(message))

                self.__to_send.append((current_socket, data))

                if len(self.__client_sockets) > len(self.__data_to_send):
                    self.__data_to_send.append(data)

                else:
                    if len(self.__data_to_send) > 0:
                        self.__data_to_send[index] = data

                self.__locations[index] = data[0]
                self.handle_client_location(self.__locations[index])

                if data[1] is not None and len(data[1]) > 0:
                    self.__chat[index] = data[1]

                self.__status[index] = data[2]

                # if 'attack' in self.__status[index]:
                #     self.__attack[index] = 0

                #  el

                self.send_to_clients(index)

        except socket.timeout:
            pass

        except ssl.SSLEOFError as e:
            print("Connection closed", e)
            self.__all_details[index]["Connected"] = 1

            self.print_client_sockets()
            self.update_database()

            self.eliminate_socket(index)

        except EOFError as e:
            print("Connection closed", e)
            self.__all_details[index]["Connected"] = 1

            self.update_database()
            self.print_client_sockets()

            self.eliminate_socket(index)

    def nearby_them(self, index):
        """

        :param index:
        """

        if not self.__locations:
            return

        else:
          #  print("locs", self.__item_locations)

            if self.__locations[index] is not None:
                e_near = list(filter(lambda m: 0 <= abs(m[1][0] - self.__locations[index][0]) <= 70
                                     and 0 <= abs(m[1][1] - self.__locations[index][1]) <= 70,
                                     self.__enemy_locations))
                w_near = list(filter(lambda m: 0 <= abs(m[1][0] - self.__locations[index][0]) <= 70
                                     and 0 <= abs(m[1][1] - self.__locations[index][1]) <= 70,
                                     self.__item_locations))

                return e_near, w_near

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
        //will be finished soon
        """

        try:
            self.__secure_socket.settimeout(0.1)
            data = pickle.loads(self.__secure_socket.recv(MAX_MSG_LENGTH))

            if not data:
                return

            else:
                decrypted_data = data

                if decrypted_data == 1:
                    self.__secure_socket.close()
                    self.__secure_socket = EncryptClient("Server", 2, "all.we.mightknow")

                    self.connect_to_security()
                    return

                unpacked_data = pickle.loads(decrypted_data)

                return unpacked_data

        except socket.timeout:
            return

    def send_to_clients(self, number):
        """

        :param number:
        """

        eligables = list(filter(lambda person: person["Client"] is not None and person["Credentials"] is not None
                                               and person != self.__all_details[number], self.__all_details))
        chat_message = f'{self.__session_users[number]}: {self.__chat[number]}'
        message = [self.__locations[number], chat_message, self.__status[number], self.__session_users[number]]

        for socks in eligables:
            try:
                socks["Client"].send(pickle.dumps(message))

            except ConnectionResetError as e:
                print("not  good", e)
                pass

            except ssl.SSLError as e:
                print("not  good",  e)
                pass

    def print_client_sockets(self):
        """

        """

        for c in self.__client_sockets:
            try:
                print("\t", c.getpeername())

            except OSError as e:
                print("old client", e)

    def eliminate_socket(self, number):
        """

        :param number:
        """

        try:
            if self.__all_details[number].get("Connected") == 1:
                self.__selector.unregister(self.__all_details[number].get("Client"))
                self.__all_details[number].get("Client").close()

                self.__client_sockets.pop(number)
                self.__all_details.pop(number)

                self.__credentials.pop(number)
                self.__locations.pop(number)

                self.__number_of_clients -= 1

        except Exception as e:
            print(e)
            return

        finally:
            return

    def update_database(self):
        """

        """

        for index in range(0, len(self.__new_credentials)):
            print(self.__login_data_base.insert_no_duplicates(values=[self.__new_credentials[index][0]],
                                                              no_duplicate_params=['Username']))
            print(self.__login_data_base.set_values(['Password'], [self.__new_credentials[index][1]], ['Username'],
                                                    [self.__new_credentials[index][0]]))

        for index in range(0, len(self.__session_users) - 1):
            if self.__weapons[index] is not None:
                weapons = (str(self.__weapons[index]["A"]) + ", " + str(self.__weapons[index]["B"]) + ", "
                           + str(self.__weapons[index]["S"]))
                items = (str(self.__weapons[index]["HPF"]) + ", " + str(self.__weapons[index]["EF"]) + ", " +
                         str(self.__weapons[index]["RHPF"]) + ", " + str(self.__weapons[index]["BEF"]))

                self.__main_data_base.set_values(['Items', 'Weapons'], [items, weapons], ['Username'],
                                                 [self.__session_users[index]])
        info, resource_info, ip_info = self.receive_info()
        self.__list_of_existing_existing_credentials, self.__list_of_existing_resources\
            = self.organize_info(info,resource_info, ip_info)

    def update_items(self):
        """

        """

        m = [loc for loc in self.__item_locations if loc[1] in self.__locations]
        print("the equal", m, self.__locations)

        if m:
            for collected in m:
                self.__item_locations.remove(collected)
                self.set_item_locations()
                print("GOT HIM")

    def kick_all(self):
        """

        """

        for sock in self.__client_sockets:
            sock.send(pickle.dumps(["LEAVE"]))
            sock.close()

    def disconnect_from_security(self):
        """

        """

        try:
            message = pickle.dumps(["EXIT"])

            self.__secure_socket.send(message)
            self.__secure_socket.close()

        except ConnectionResetError as e:
            print(e)
            return

    def get_local_client_details(self):
        """

        :return:
        """

        return self.__main_data_base, self.__login_data_base, self.__ips_data_base

    def get_load_balancer_ip(self):
        """
        Returns:
            str: The IP address of the "load_balancer" container or None if not found.
        """

        ip_address = os.getenv("LOAD_BALANCER_IP")

        if ip_address:
            return ip_address
        else:
            return socket.gethostbyname(socket.gethostname())


def main():
    """
    Main function
    """

    main_data_base = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])
    ips_data_base = DatabaseManager("IPs", PARAMETERS["IPs"])

    login_data_base = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])
    numbers = TheNumbers().run()

    server = Server(main_data_base, login_data_base, ips_data_base, numbers)
    server.run()


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    main()
