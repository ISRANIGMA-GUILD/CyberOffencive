import socket
from settings import *
from DatabaseCreator import *
from login import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
from wrapper_of_the_server_socks import *
from wrapper_of_the_client_socks import *
from clientpasswordgen import *
from serverpassword import *
from interesting_numbers import *
from movment_logic import *
from map import MapRenderer
from collisiongrid import CollisionGrid
import os
import re
import threading
import pickle
import selectors
import errno
from random import *
import time
from dnssec_client import ServerDiscoveryClient

THE_USUAL_IP = '0.0.0.0'
MY_IP = socket.gethostbyname(socket.gethostname())
MAX_MSG_LENGTH = 16000
LOCAL_HOST = '127.0.0.1'
PARAMETERS = {"PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons'],
              "NODUP": ['Username', 'Password'], "DUP": ['Status', 'Items', 'Weapons'],
              "IPs": ["IP", "MAC"], "Users": ['Username'], "STAT": ["Status"], "NET": ["IP", "MAC", "Status"]}


class Server:

    def __init__(self, main_data_base, login_data_base, ips_data_base, number, username_database,
                 stat_data_base, net_base):
        self.__load_balance_socket = EncryptClient("Secret", number, "load_balancer").run()

        self.__load_balance_ip = self.get_load_balancer_ip()
        print(self.__load_balance_ip)
        self.__load_balance_port = 1800

        self.__main_data_base = main_data_base
        self.__login_data_base = login_data_base

        self.__ips_data_base = ips_data_base
        self.__username_database = username_database

        self.__stat_database = stat_data_base
        self.__net_base = net_base

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
        self.__items = []

        self.__hp = []
        self.__energy = []

        self.__session_users = []
        self.__to_send = []

        self.__data_to_send = []
        self.__client_sockets = []

        self.__selector = selectors.DefaultSelector()
        self.__list_of_existing_resources = []

        self.__list_of_existing_existing_credentials = []
        self.collision_grid = self.create_collision_grid()

        self.__enemy_locations = []
        self.__killed_enemies = []

        self.__collected_items = []
        self.__item_locations = []
        self.__e_possabilities = ["BSS", "BS", "CRS", "CS", "RGS", "RS", "GOB", "FRE"]

        self.__w_possabilities = ["A", "B", "S", "HPF", "EF", "RHPF", "BEF"]
        self.__server_name = "load_balancer"

        self.__zone = {}
        self.__id = []
        self.__items_ids = []
        self.__data_storage = []

    def run(self):
        """

        """

        # """:TODO(finished?): Use load balancer with a main database and servers with their local ones"""#
        # """:TODO(almost finished): Loading screen between menu and login screens """#
        # """:TODO(almost finished): Try-except on everything """#
        # """:TODO(almost finished): Show weapons when attacking"""#
        # """:TODO: Make sure clients move smoothly move between servers"""#
        # """:TODO: Make a whitelist of processes NO MATTER CLIENT FRIENDLY or NOT"""#
        # """:TODO(almost finished): Erase items and enemies from client side to make sure they dont still appear if collected or killed"""#
        # """:TODO(almost finished): Database updates correctly even if server is closed"""#
        # """:TODO(If there is time): If banned you can't connect

        info, resource_info, ip_info = self.receive_info()
        self.__list_of_existing_existing_credentials, self.__list_of_existing_resources = self.organize_info(info,
                                                                                                             resource_info,
                                                                                                             ip_info)
        self.set_ids()
        self.set_locations()

        self.set_item_locations()
        self.__list_of_banned_users = [[self.__list_of_existing_existing_credentials[i][0],
                                        self.__list_of_existing_existing_credentials[i][1],
                                        self.__list_of_existing_existing_credentials[i][0]]
                                       for i in range(0, len(self.__list_of_existing_resources))
                                       if self.__list_of_existing_resources[i][0] == "banned"]

        print("Server is up and running")

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

    def set_ids(self):
        """
        Updates list of enemy locations, adds enemies if there are less than 100 enemies in total
        """

        for i in range(0, 101):
            enemy_is = f'{i}'
            self.__id.append(enemy_is)
        
        for i in range(0, 101):
            item_is = f'{i}'
            self.__items_ids.append(item_is)

    def set_locations(self):
        """
        Updates list of enemy locations, adds enemies if there are less than 100 enemies in total
        """

        if self.__enemy_locations:
            used = [re.findall(r'\d+', i[0])[0] for i in self.__enemy_locations]
            unused = list(filter(lambda x: x not in used, self.__id))

        else:
            unused = self.__id

        while len(self.__enemy_locations) < 101:

            for identity in unused:
                enemy_is = f'{choice(self.__e_possabilities)}{identity}'
                self.__enemy_locations.append((enemy_is, (randint(1000, 10000), randint(1000, 10000))))

    def set_item_locations(self):
        """
        Updates list of item locations, adds enemies if there are less than 100 enemies in total
        """

        if self.__item_locations:
            used = [re.findall(r'\d+', i[0])[0] for i in self.__item_locations]
            unused = list(filter(lambda x: x not in used, self.__items_ids))
        
        else:
            unused = self.__items_ids
        

        while len(self.__item_locations) < 101:
            for identity in unused:
                item_is = f'{choice(self.__w_possabilities)}{identity}'
                self.__item_locations.append((item_is, (randint(1000, 10000), randint(1000, 10000))))

    def connect_to_load_socket(self):
        """

        """

        g = 1

        while 1:
            try:
                self.__load_balance_socket.connect((self.__load_balance_ip, self.__load_balance_port))
                their_pass = Verifier(480).run()

                self.__load_balance_socket.send(pickle.dumps([GetPassword(460).run()]))
                self.__load_balance_socket.settimeout(0.5)

                data = pickle.loads(self.__load_balance_socket.recv(1024))

                if data[0] != their_pass:
                    self.__load_balance_socket.close()
                    g = 0

                else:
                    print("Hi load balancer")
                    g = 0

                    # Receive configuration data from the load balancer
                    data = self.__load_balance_socket.recv(1024)
                    configuration = pickle.loads(data)

                    self.__server_name = configuration['server_name']
                    self.__zone = configuration['zone']

                    print(f"Received configuration: Server Name - {self.__server_name}, Zone - {self.__zone}")

                if g == 0:
                    break

            except socket.timeout as e:
                print(e)

            except ConnectionRefusedError as e:
                print(e)

            except ConnectionResetError as e:
                print(e)

            except OSError as e:
                print(e)

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

    def handle_client_location(self, client_location, temp, index):
        """
        Check client location and notify load balancer if out of zone.
        :param index:
        :param temp:
        :param client_location:
        """

        if temp:
            print("hi")
            self.send_message_to_load_balancer({'type': 'out_of_zone', 'location': client_location,
                                                'credentials': self.__credentials[index], 'status': self.__status[index]
                                                ,'items': self.__items[index]})
        key = list(self.__zone.keys())[0]
        x, y = client_location

        if self.__server_name == 'buffer_zone':
            zone_1 = self.__zone['ZoneBuffer']['min_x1'], self.__zone['ZoneBuffer']['max_x1'], \
                self.__zone['ZoneBuffer']['min_y1'], self.__zone['ZoneBuffer']['max_y1']

            zone_2 = self.__zone['ZoneBuffer']['min_x2'], self.__zone['ZoneBuffer']['max_x2'], \
                self.__zone['ZoneBuffer']['min_y2'], self.__zone['ZoneBuffer']['max_y2']

            if (zone_1[0] <= x <= zone_1[1] and zone_1[2] <= y <= zone_1[3]) or (
                    zone_2[0] <= x <= zone_2[1] and zone_2[2] <= y <= zone_2[3]):
                print("Client location within buffer zone.")

            else:
                print("Client location out of buffer zones.")
                self.send_message_to_load_balancer({'type': 'out_of_zone', 'location': client_location,
                                                    'client_data': []})

        else:
            min_x, max_x, min_y, max_y = self.__zone['min_x'], self.__zone['max_x'], self.__zone['min_y'], self.__zone[
                'max_y']
            if min_x <= x <= max_x and min_y <= y <= max_y:
                pass

            else:
                print(f"Client location {client_location} out of assigned zone.")
                self.send_message_to_load_balancer({'type': 'out_of_zone', 'location': client_location,
                                                    'server': self.__server_name, 'client_data': []})

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
            self.__load_balance_socket.settimeout(0.01)
            data = self.__load_balance_socket.recv(1024)

            if data:
                configuration = pickle.loads(data)
                self.__server_name = configuration['server_name']

                self.__zone = configuration['zone']
                print(f"Received configuration: Server Name - {self.__server_name}, Zone - {self.__zone}")

            else:
                print("Load balancer closed the connection.")
                self.__load_balance_socket.close()

        except socket.timeout as e:
            print("error when receiveing another from load balancer", e)

        except ssl.SSLError as e:
            print(f"SSL error: {e}")

        except Exception as e:
            print(f"Error: {e}")

    def receive_data_from_load_balancer(self):
        """

        """

        try:
            self.__load_balance_socket.settimeout(0.01)
            data = self.__load_balance_socket.recv(1024)

            if data:
                new_client_info = pickle.loads(data)
                self.add_new_client(new_client_info)

        except socket.timeout as e:
           # print("timeout load balancer", e)
            pass

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

    def check_for_banned(self, connection, client_address, number):
        """

        :param connection:
        :param client_address:
        :param number:
        """

        print(client_address)
        if (client_address[0] in self.__banned_ips or getmacbyip(client_address[0]) in self.__banned_macs
                or Ether().src in self.__banned_macs):
            self.__all_details[number]["Connected"] = 1
         #   connection.close()
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

        update_interval = 1 / 60  # Seconds (adjust as needed for responsiveness)
        update_interval2 = 1 / 30  # Seconds (adjust as needed for responsiveness)
        update_interval3 = 1 / 2  # Seconds (adjust as needed for responsiveness)
        
        last_update_time = time.time()
        last_update_time2 = time.time()
        last_update_time3 = time.time()

        previous_item = self.__item_locations
        previous_enemy = self.__enemy_locations

        while 1:
            try:

                self.new_handling()

                current_time = time.time()
                current_time2 = time.time()
                current_time3 = time.time()

                if current_time - last_update_time >= update_interval:
                    self.update_game_state()
                    if (current_time2 - last_update_time2 >= update_interval2 and
                            (self.__enemy_locations != previous_enemy or self.__item_locations != previous_item)):
                        self.inform_all()
                        if current_time3 - last_update_time3 >= update_interval3:
                            self.__killed_enemies = []
                            self.__collected_items = []
                            last_update_time3 = current_time3

                        previous_enemy = self.__enemy_locations
                        previous_item = self.__item_locations
                        last_update_time2 = current_time2
                    last_update_time = current_time

                

            except ConnectionResetError as e:
                print("Server will end service")
                print("e", e)

                self.update_database()
                self.__login_data_base.close_conn()

                self.__main_data_base.close_conn()

                self.__ips_data_base.close_conn()
                break

            except KeyboardInterrupt as e:
                print("Server will end service")
                print("e", e)

                self.update_database()
                self.kick_all()

                self.__login_data_base.close_conn()
                self.__main_data_base.close_conn()

                self.__ips_data_base.close_conn()
                break

            except Exception as e:
                print("Server will end service")
                print(e)

                self.update_database()
                self.kick_all()

                self.__login_data_base.close_conn()
                self.__main_data_base.close_conn()

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

        if self.__number_of_clients - 1 >= len(self.__session_users) or len(self.__session_users) == 0:
            self.__session_users.append(None)

    def new_handling(self):
        """

        """
        events = self.__selector.select(0)

        for key, mask in events:
            self.update_credential_list()
            self.update_database()

            callback = key.data
            callback(key.fileobj, mask)

            self.receive_data_from_load_balancer()

    def update_game_state(self):

        self.update_items()
        self.update_enemies()

        self.set_locations()
        self.set_item_locations()

    def inform_all(self):

        if len(self.__credentials) <= len(self.__session_users):

            for index in range(0, len(self.__client_sockets)):
                try:
                    nearby_sprites = self.nearby_them(index)

                    if nearby_sprites:
                        self.__client_sockets[index].send(pickle.dumps(nearby_sprites))

                except Exception as e:
                    print("Connection closedh", e)
                    self.__all_details[index]["Connected"] = 1

                    self.print_client_sockets()
                    self.update_database()

                    self.eliminate_socket(index)


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
            connection.settimeout(0.003)
            their_pass = pickle.loads(connection.recv(MAX_MSG_LENGTH))

            if their_pass[0] != passw:
                print("shut up", Ether().src)
                if getmacbyip(client_address[0]) == 'ff:ff:ff:ff:ff:ff':

                    print("banned banned", self.__ips_data_base.insert_no_duplicates(values=[client_address[0], Ether().src],
                                                              no_duplicate_params=["IP", "MAC"]))
                    self.__net_base.set_values(["Status"], ["BANNED"], ["IP", "MAC"],
                                                    [client_address[0], Ether().src])
                    self.__banned_ips.append(client_address[0])
                    self.__banned_macs.append(getmacbyip(client_address[0]))

                else:
                    self.__ips_data_base.insert_no_duplicates(
                        values=[client_address[0], getmacbyip(client_address[0])],
                        no_duplicate_params=["IP", "MAC"])

                    self.__net_base.set_values(["Status"], ["BANNED"], PARAMETERS["IPs"],
                                                [client_address[0], getmacbyip(client_address[0])])
                    self.__banned_ips.append(client_address[0])
                    self.__banned_macs.append(getmacbyip(client_address[0]))

                return

            self.check_for_banned(connection, client_address, index)

        except socket.timeout as e:
            print("Didn't receive this time a client connection", e)
            connection.close()
            return

        except pickle.UnpicklingError as e:
            print("BAN!", e, Ether().src)

            if getmacbyip(client_address[0]) == 'ff:ff:ff:ff:ff:ff':

                print("banned banned", self.__ips_data_base.insert_no_duplicates(values=[client_address[0], Ether().src],
                                                                                 no_duplicate_params=["IP", "MAC"]))
                self.__net_base.set_values(["Status"], ["BANNED"], ["IP", "MAC"],
                                                [client_address[0], Ether().src])
                self.__banned_ips.append(client_address[0])
                self.__banned_macs.append(getmacbyip(client_address[0]))

            else:
                self.__ips_data_base.insert_no_duplicates(
                    values=[client_address[0], getmacbyip(client_address[0])],
                    no_duplicate_params=["IP", "MAC"])

                self.__net_base.set_values(["Status"], ["BANNED"], PARAMETERS["IPs"],
                                                [client_address[0], getmacbyip(client_address[0])])
                self.__banned_ips.append(client_address[0])
                self.__banned_macs.append(getmacbyip(client_address[0]))

            return

        try:
            connection.send(pickle.dumps([my_pass]))
            print("New client joined!", client_address)

            self.__to_send.append((current_socket, "yay"))
            self.check_for_banned(connection, client_address, index)

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
            current_socket.settimeout(0.05)
            data = pickle.loads(current_socket.recv(MAX_MSG_LENGTH))

            if "EXIT" in data[0]:
                self.__all_details[index]["Connected"] = 1
                self.__items[index] = data[2]
                self.update_database()

                current_socket.send(pickle.dumps(["OK"]))

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

        except socket.timeout as e:
            print("Still waiting for login from client", index, e)
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
         Send any updates to chosen client
        :param current_socket: The socket of the client
        :param mask: Damascus
        """
        target = list(filter(lambda person: person["Client"] == current_socket and person["Credentials"] is not None,
                             self.__all_details))[0]
        index = self.__all_details.index(target)
        data = ""

        try:
            current_socket.settimeout(0.03)
            data = pickle.loads(current_socket.recv(MAX_MSG_LENGTH))

            # If client has quit save their data
            if "EXIT" in data[0]:
                print("Connection closedg")
                self.__all_details[index]["Connected"] = 1

                self.__items[index] = data[2]
                self.update_database()
                
                current_socket.send(pickle.dumps(["OK"]))

                self.eliminate_socket(index)
                self.print_client_sockets()

            # If client has logged in and there are clients update them

            elif len(self.__credentials) <= len(self.__session_users) and type(data) is not tuple and len(data) != 2:

                self.__to_send.append((current_socket, data))

                if len(self.__client_sockets) > len(self.__data_to_send):
                    self.__data_to_send.append(data)

                else:
                    if len(self.__data_to_send) > 0:
                        self.__data_to_send[index] = data

                self.__locations[index] = (self.__session_users[index], data[0])
                self.handle_client_location(self.__locations[index][1], [], index)

                if data[1] is not None and len(data[1]) > 0:
                    self.__chat[index] = data[1]

                self.__status[index] = data[2]
                self.send_to_clients(index)
            
            elif len(data) == 2:
                print("meow",data)
                if data[0] == "kill":
                    for stuff in self.__enemy_locations:
                        if stuff[0] == data[1]:
                            print("kill him")
                            self.__enemy_locations.remove(stuff)
                            self.__killed_enemies.append(data[1])

                elif data[0] == "collected":
                    for stuff in self.__item_locations:
                        if stuff[0] == data[1]:
                            print("collected")
                            self.__item_locations.remove(stuff)
                            self.__collected_items.append(data[1])
            
            

        except socket.timeout as e:
            print("meow", e)
            pass

        except ssl.SSLEOFError as e:
            print("Connection closedm", e)
            self.__all_details[index]["Connected"] = 1

            self.print_client_sockets()
            self.update_database()

            self.eliminate_socket(index)

        except ssl.SSLError as e:
            print("Connection closedm", e)
            self.__all_details[index]["Connected"] = 1

            self.print_client_sockets()
            self.update_database()

            self.eliminate_socket(index)

        except EOFError as e:
            print("Connection closedn", e)
            self.__all_details[index]["Connected"] = 1

            self.update_database()
            self.print_client_sockets()

            self.eliminate_socket(index)

    def nearby_them(self, index):
        """
         Checks for each player which items and enemies are in visible distance
        :param index: The index of the player in the list of locations
        :return: List of enemy, item locations which are in visible distance for the client
        """

        if not self.__locations:
            return

        else:

            if self.__locations[index] is not None:
                e_near = list(filter(lambda m: 0 <= abs(m[1][0] - self.__locations[index][1][0]) <= 1000
                                               and 0 <= abs(m[1][1] - self.__locations[index][1][1]) <= 1000,
                                     self.__enemy_locations))
                w_near = list(filter(lambda m: 0 <= abs(m[1][0] - self.__locations[index][1][0]) <= 1000
                                               and 0 <= abs(m[1][1] - self.__locations[index][1][1]) <= 1000,
                                     self.__item_locations))
                e_killed = self.__killed_enemies
                i_collected = self.__collected_items

                return ["eeee", e_near, w_near, e_killed, i_collected]

    def send_to_clients(self, number):
        """

        :param number:
        """

        eligables = list(filter(lambda person: person["Client"] is not None and person["Credentials"] is not None
                                               and person != self.__all_details[number], self.__all_details))
        chat_message = f'{self.__session_users[number]}: {self.__chat[number]}'
        message = [self.__locations[number][1], chat_message, self.__status[number], self.__session_users[number]]

        for socks in eligables:
            try:
                socks["Client"].send(pickle.dumps(message))

            except ConnectionResetError as e:
                print("not  good", e)
                pass

            except ssl.SSLError as e:
                print("not  good", e)
                pass

    def send_from_clients(self, number):
        """
        on connection update every client
        :param number:
        """

        eligables = list(filter(lambda person: person["Client"] is not None and person["Credentials"] is not None
                                and person != self.__all_details[number], self.__all_details))

        for socks in eligables:
            chat_message = f'{self.__session_users[number]}: {self.__chat[number]}'
            message = [self.__locations[number][1], chat_message, self.__status[number], self.__session_users[number]]

            try:
                socks["Client"].send(pickle.dumps(message))

            except ConnectionResetError as e:
                print("not  good", e)
                pass

            except ssl.SSLError as e:
                print("not  good", e)
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
            self.__username_database.insert_no_duplicates(values=[self.__new_credentials[index][0]],
                                                                        no_duplicate_params=['Username'])

            self.__main_data_base.set_values(['Password'], [self.__new_credentials[index][1]],
                                             ['Username'], [self.__new_credentials[index][0]])

        for index in range(0, len(self.__session_users) - 1):
            if self.__items[index] is not None:
                weapons = (str(self.__items[index]["A"]) + ", " + str(self.__items[index]["B"]) + ", "
                           + str(self.__items[index]["S"]))
                items = (str(self.__items[index]["HPF"]) + ", " + str(self.__items[index]["EF"]) + ", " +
                         str(self.__items[index]["RHPF"]) + ", " + str(self.__items[index]["BEF"]))

                self.__main_data_base.set_values(['Items', 'Weapons'], [items, weapons], ['Username'],
                                                 [self.__session_users[index]])
        info, resource_info, ip_info = self.receive_info()
        self.__list_of_existing_existing_credentials, self.__list_of_existing_resources = (
            self.organize_info(info, resource_info, ip_info))

    def update_items(self):
        """

        """

        m = [loc for loc in self.__item_locations if loc[1] in self.__locations]
        # print("the equal", m, self.__locations)

        if m:
            for collected in m:
                self.__item_locations.remove(collected)
                self.set_item_locations()
                print("GOT HIM")

    def update_enemies(self):
        """

        """

        m = [loc for loc in self.__enemy_locations]
        # print("the equal", m, self.__enemy_locations)

        if m:
            g = EnemyManager(self.collision_grid)
            self.__enemy_locations = g.update_locations(self.__enemy_locations, self.__locations)

    def create_collision_grid(self):
        """Creates the collision grid for the server."""
        map_renderer = MapRenderer()  # Create MapRenderer instance
        collision_grid = CollisionGrid(map_renderer.tmx_data.width, map_renderer.tmx_data.height,
                                       64, 64)

        for obj in map_renderer.get_objects():
            collision_grid.add_to_grid(obj)

        return collision_grid

    def kick_all(self):
        """

        """

        for sock in self.__client_sockets:
            try:
                sock.send(pickle.dumps(["LEAVE"]))
                sock.settimeout(0.5)

                data = pickle.loads(sock.recv(1024))
                self.__items[self.__client_sockets.index(sock)] = data

                self.update_database()

                sock.close()

            except socket.timeout as e:
                print("To bad", e)
                sock.close()

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
        print(ip_address, "ip address")

        if ip_address:
            return ip_address
        elif ServerDiscoveryClient().discover_server():
            return ServerDiscoveryClient().discover_server()
        else:
            return socket.gethostbyname(socket.gethostname())

def main():
    """
    Main function
    """

    pygame.init()
    pygame.mixer.pre_init(44100, 16, 2, 4096)
    pygame.font.init()

    # Create a dummy, invisible display (1x1 pixel)
    screen = pygame.display.set_mode((1, 1), pygame.NOFRAME, BITS_PER_PIXEL)
    main_data_base = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])
    ips_data_base = DatabaseManager("IPs", PARAMETERS["IPs"])

    login_data_base = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])
    username_database = DatabaseManager("PlayerDetails", PARAMETERS["Users"])
    stat_data_base = DatabaseManager("IPs", PARAMETERS["STAT"])
    net_base = DatabaseManager("IPs", PARAMETERS["NET"])
    numbers = TheNumbers().run()

    server = Server(main_data_base, login_data_base, ips_data_base, numbers, username_database, stat_data_base, net_base)
    server.run()


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    main()
