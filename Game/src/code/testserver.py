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
PARAMETERS = {"PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons'],
              "NODUP": ['Username', 'Password'], "DUP": ['Status', 'Items', 'Weapons'],
              "IPs": ["IP", "MAC"], "Users": ['Username'], "STAT": ["Status"], "NET": ["IP", "MAC", "Status"]}


class Server:
    ##TODO: Make sure time does not impact success or failure in login##
    def __init__(self, main_data_base, login_data_base, ips_data_base, number, username_database,
                 stat_data_base, net_base):
        self.__load_balance_socket = EncryptClient("Secret", number, "load_balancer").run()
        self.__load_balance_ip = self.get_load_balancer_ip()

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

        self.__server_name = ""
        self.__zone = {}

        self.__id = []
        self.__items_ids = []

        self.__data_storage = []
        self.__who = None

    def run(self):
        """

        """

        # """:TODO(almost finished): Try-except on everything """#
        # """:TODO(almost finished): Database updates correctly even if server is closed"""#
        # """:TODO(??finished????): If banned you can't connect
        # """:TODO: If server closes send all clients to load balancer
        # """:TODO(??finished????): Do the big merge, finish everything today

        info, resource_info, ip_info = self.receive_info()
        self.__list_of_existing_existing_credentials, self.__list_of_existing_resources = self.organize_info(info,
                                                                                                             resource_info,
                                                                                                             ip_info)

        self.__list_of_banned_users = [[self.__list_of_existing_existing_credentials[i][0],
                                        self.__list_of_existing_existing_credentials[i][1],
                                        self.__list_of_existing_existing_credentials[i][0]]
                                       for i in range(0, len(self.__list_of_existing_resources))
                                       if self.__list_of_existing_resources[i][0] == "banned"]

        print("Server is up and running")

        self.connect_to_load_socket()
        self.set_ids()
        self.set_locations()

        self.set_item_locations()
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

        locations = list(self.__zone.values())

        if self.__enemy_locations:
            used = [re.findall(r'\d+', i[0])[0] for i in self.__enemy_locations]
            unused = list(filter(lambda x: x not in used, self.__id))

        else:
            unused = self.__id

        while len(self.__enemy_locations) < 101:

            for identity in unused:
                enemy_is = f'{choice(self.__e_possabilities)}{identity}'
                if enemy_is in self.__killed_enemies:
                    self.__killed_enemies.remove(enemy_is)
                self.__enemy_locations.append((enemy_is, (randint(locations[0], locations[1]),
                                                          randint(locations[2], locations[3]))))

    def set_item_locations(self):
        """
        Updates list of item locations, adds enemies if there are less than 100 enemies in total
        """

        locations = list(self.__zone.values())

        if self.__item_locations:
            used = [re.findall(r'\d+', i[0])[0] for i in self.__item_locations]
            unused = list(filter(lambda x: x not in used, self.__items_ids))
        
        else:
            unused = self.__items_ids

        while len(self.__item_locations) < 101:
            for identity in unused:
                item_is = f'{choice(self.__w_possabilities)}{identity}'
                if item_is in self.__collected_items:
                    self.__collected_items.remove(item_is)
                self.__item_locations.append((item_is, (randint(locations[0], locations[1]),
                                                        randint(locations[2], locations[3]))))

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
            if self.__load_balance_socket is None or self.__load_balance_socket.fileno() == -1:
                print("Socket is closed. Reinitializing socket.")
                self.initialize_load_balance_socket()  # Method to reinitialize the socket
                print("Socket reinitialized.", message)

            print(f"Message sent to Load Balancer1: {message}")
            self.__load_balance_socket.send(pickle.dumps(message))
            print(f"Message sent to Load Balancer: {message}")

        except Exception as e:
            print(f"Failed to send message: {e}")

            if isinstance(e, socket.error):
                print("Attempting to reinitialize socket after send failure.")
                self.initialize_load_balance_socket()

        except KeyboardInterrupt as e:
            print(e)

    def initialize_load_balance_socket(self):
        """

        """

        try:
            if self.__load_balance_socket:
                self.__load_balance_socket.close()

            numbers = TheNumbers().run()
            self.__load_balance_socket = EncryptClient("Secret", numbers, "load_balancer").run()

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

            print("Load balancer socket reinitialized and connected.")

        except Exception as e:
            print(f"Failed to reinitialize and connect load balancer socket: {e}")
            self.__load_balance_socket = None

    def handle_client_location(self, client_location, temp, index):
        """
        Check client location and notify load balancer if out of zone.
        :param index:
        :param temp:
        :param client_location:
        """

        key = list(self.__zone.keys())[0]
        x, y = client_location

        if self.__server_name == 'Server 5':
            zone_1 = self.__zone['ZoneBuffer']['min_x1'], self.__zone['ZoneBuffer']['max_x1'], \
                self.__zone['ZoneBuffer']['min_y1'], self.__zone['ZoneBuffer']['max_y1']

            zone_2 = self.__zone['ZoneBuffer']['min_x2'], self.__zone['ZoneBuffer']['max_x2'], \
                self.__zone['ZoneBuffer']['min_y2'], self.__zone['ZoneBuffer']['max_y2']

            if (zone_1[0] <= x <= zone_1[1] and zone_1[2] <= y <= zone_1[3]) or (
                    zone_2[0] <= x <= zone_2[1] and zone_2[2] <= y <= zone_2[3]):
                print("Client location within buffer zone.")

            else:
                print("Client location out of buffer zones.")
                self.send_message_to_load_balancer({'message_status': 'move', 'type': 'out_of_zone',
                                                    'location': client_location,
                                                    'credentials': self.__credentials[index],
                                                    'status': self.__status[index]
                                                    , 'items': self.__items[index]})

        else:
            min_x, max_x, min_y, max_y = self.__zone['min_x'], self.__zone['max_x'], self.__zone['min_y'], self.__zone[
                'max_y']
            if min_x <= x <= max_x and min_y <= y <= max_y:
                pass

            else:
                print(f"Client location {client_location} out of assigned zone.")
                self.send_message_to_load_balancer({'message_status': 'move', 'type': 'out_of_zone',
                                                    'location': client_location,
                                                    'credentials': self.__credentials[index],
                                                    'status': self.__status[index]
                                                    , 'items': self.__items[index]})

    def receive_data_from_load_balancer(self, sock, index):
        """

        """

        try:
            self.__load_balance_socket.settimeout(0.003)
            data = self.__load_balance_socket.recv(16000)

            if data:
                if pickle.loads(data)['message_status'] == 'do_add':
                    return True

                elif pickle.loads(data)['message_status'] == 'dont':
                    return False

                elif pickle.loads(data)['message_status'] == 'move':

<<<<<<< HEAD
                  #  temp = True  ########################################################################### for testing
               #     self.handle_client_location(self.__locations[index][1], temp, index)
=======
                    # temp = True  ########################################################################### for testing
                    # self.handle_client_location(self.__locations[index][1], temp, index)
>>>>>>> ed47ea8cd1c749758a0f62ce89be32703f95d4f5
                    new_client_info = pickle.loads(data)
                    self.send_client_to_other_server(new_client_info, sock)
                    print("he did it")

        except socket.timeout as e:
            pass

        except Exception as e:
            print("Failed to receive data from load balancer:", e)
            # self.__load_balance_socket.close()

    def send_client_to_other_server(self, client_info, sock):
        """
        send to client to connect to different server
        :param client_info:

        Args:
            sock:
        """
        t = client_info['ip']
        ip = t[0]

        print("is it a socket?", ip, client_info['credential'])
        message = ["EXIT", ip, client_info['credential']]

        print(f"the massage is: {message}")
        sock.send(pickle.dumps(message))

        print(f"send message to client to leave the server and to go to{client_info['ip']}")

    def check_for_banned(self, client_address, number):
        """

        :param client_address:
        :param number:
        """

        print(client_address)
        if (client_address[0] in self.__banned_ips or getmacbyip(client_address[0]) in self.__banned_macs
                or (getmacbyip(client_address[0]) == 'ff:ff:ff:ff:ff:ff' and Ether().src in self.__banned_macs)):
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

        update_interval = 1 / 60  # Seconds (adjust as needed for responsiveness)
        update_interval2 = 1 / 2  # Seconds (adjust as needed for responsiveness)
        update_interval3 = 1 / 2
        
        last_update_time = time.time()
        last_update_time2 = time.time()
        last_update_time3 = time.time()

        while 1:
            try:

                self.new_handling()

                current_time = time.time()
                current_time2 = time.time()
                current_time3 = time.time()

                if current_time - last_update_time >= update_interval:
                    self.update_game_state()
                    last_update_time = current_time

                if current_time2 - last_update_time2 >= update_interval2:
                    self.inform_all()
                    last_update_time2 = current_time2

                if current_time3 - last_update_time3 >= update_interval3:
                    self.send_from_clients()
                    last_update_time3 = current_time3

            except ConnectionResetError as e:
                print("Server will end service")
                print("e", e)
                self.update_database()

            except KeyboardInterrupt as e:
                print("Server will end service")
                print("e", e)

                self.update_database()
                self.kick_all()

                self.__login_data_base.close_conn()
                self.__main_data_base.close_conn()

                self.__ips_data_base.close_conn()
                self.__load_balance_socket.close()
                break

            except Exception as e:
                print("The general error", e)
                self.update_database()

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

        if self.__number_of_clients - 1 >= len(self.__data_storage) or len(self.__data_storage) == 0:
            self.__data_storage.append(None)

    def new_handling(self):
        """

        """
        events = self.__selector.select(0)

        for key, mask in events:
            self.update_credential_list()
            self.update_database()

            callback = key.data
            callback(key.fileobj, mask)

            self.inform_all()

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

        passw = GetPassword(128).run()
        my_pass = Verifier(256).run()

        connection, client_address = current_socket.accept()
        self.check_for_banned(client_address, index)

        try:
            connection.settimeout(0.003)
            their_pass = pickle.loads(connection.recv(MAX_MSG_LENGTH))

            if their_pass[0] != passw:
                print("shut up")
                self.ban_client(client_address)

            else:

                connection.send(pickle.dumps([my_pass]))
                print("New client joined!", client_address)

                self.check_for_banned(client_address, index)
                self.__client_sockets.append(connection)

                self.__all_details[index]["Client"] = connection
                self.__all_details[index]["Sockets"] = current_socket

                self.__number_of_clients += 1
                self.print_client_sockets()

                connection.setblocking(False)
                self.__selector.register(connection, selectors.EVENT_READ, self.receive_login)

        except socket.timeout as e:
            print("Didn't receive this time a client connection", e)
            return

        except pickle.UnpicklingError as e:
            print("BAN!", e)
            self.ban_client(client_address)
            return

        except ConnectionResetError as e:
            print(e)
            connection.close()

    def ban_client(self, client_address):
        """

        :param client_address:
        :return:
        """

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

    def receive_login(self, current_socket, mask):
        """

        :param current_socket:
        :param mask:
        """

        target = list(filter(lambda person: person["Client"] == current_socket and person["Credentials"] is None,
                             self.__all_details))[0]
        index = self.__all_details.index(target)

        try:
            current_socket.settimeout(0.003)
            data = pickle.loads(current_socket.recv(MAX_MSG_LENGTH))

            if "EXIT" in data[0]:
                self.__all_details[index]["Connected"] = 1
                self.__items[index] = data[2]

                self.update_database()
                current_socket.send(pickle.dumps(["OK"]))

                self.print_client_sockets(data[2])
                self.eliminate_socket(index)

            else:
                if type(data) is tuple:

                    loging = Login(self.__all_details[index], self.__list_of_existing_existing_credentials,
                                   self.__list_of_existing_resources, self.__credentials, index,
                                   self.__new_credentials, self.__list_of_banned_users, data, self.__zone,
                                   self.__load_balance_socket, self.__server_name)

                    (self.__all_details[index], self.__credentials, self.__list_of_existing_existing_credentials,
                     self.__list_of_existing_resources, self.__new_credentials) = loging.run()

                    if self.__all_details[index].get("Credentials") is not None:

                        self.__session_users[index] = self.__all_details[index].get("Credentials")[0]
                        self.__who = self.__all_details[index].get("Credentials")[0]

                        self.print_client_sockets()
                        self.__selector.modify(current_socket, selectors.EVENT_READ, self.update_clients)

                    else:
                        print("Connection closedg you forken dummy", data, self.__all_details[index])
                        self.__all_details[index]["Connected"] = 1

                        if len(data) >= 3:
                            self.__items[index] = data[2]

                        self.update_database()
                        current_socket.send(pickle.dumps(["OK"]))

                        self.eliminate_socket(index)
                        self.print_client_sockets()

        except socket.timeout as e:
            print("Still waiting for login from client", index, e)

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

        self.receive_data_from_load_balancer(self.__client_sockets[index], index)

        try:
            current_socket.settimeout(0.003)
            data = pickle.loads(current_socket.recv(MAX_MSG_LENGTH))

            # If client has quit save their data
            if "EXIT" in data[0]:
                print("Connection closedg")
                self.__all_details[index]["Connected"] = 1
                self.__items[index] = data[2]

                self.update_database()
                current_socket.send(pickle.dumps(["OK"]))

                self.eliminate_socket(index)
                self.print_client_sockets(data[2])

            # If client has logged in and there are clients update them

            elif len(self.__credentials) <= len(self.__session_users) and type(data) is not tuple and len(data) != 2:

                if len(self.__client_sockets) > len(self.__data_to_send):
                    self.__data_to_send.append(data)

                else:
                    if len(self.__data_to_send) > 0:
                        self.__data_to_send[index] = data

                self.__locations[index] = (self.__session_users[index], data[0])
                temp = True ########################################################################### for testing
                self.handle_client_location(self.__locations[index][1], temp, index)

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
        chat_message = f'{self.__chat[number]}'
        message = [self.__locations[number][1], chat_message, self.__status[number], self.__session_users[number]]

        self.__data_storage[number] = (self.__session_users[number], message)

        for socks in eligables:
            try:
                socks["Client"].send(pickle.dumps(message))

            except ConnectionResetError as e:
                print("not  good", e)

            except ssl.SSLError as e:
                print("not  good", e)

    def send_from_clients(self):
        """
         on connection update every client
        """

        try:
            eligables = list(filter(lambda person: person["Client"] is not None and person["Credentials"] is not None
                                    ,self.__all_details))
            for socks in eligables:
                if socks["Credentials"] is not None:
                    current = self.__credentials.index(socks["Credentials"])
                    clear_data = [data for data in self.__data_storage if data is not None]

                    if current in clear_data:
                        for message in clear_data:
                            if message is not None and current != self.__session_users.index(message[0]):
                                if (abs(message[0][0] - clear_data[current][0][0]) <= 1500 or
                                        abs(message[0][1] - clear_data[current][0][1]) <= 1500):
                                    socks["Client"].send(pickle.dumps(message[1]))

        except ConnectionResetError as e:
            print("not  good", e)

        except ssl.SSLError as e:
            print("not  good", e)

    def print_client_sockets(self, items=None):
        """

        """

        self.how_many_clients(items)

        for c in self.__client_sockets:
            try:
                print("\t", c.getpeername())

            except OSError as e:
                print("old client", e)

    def how_many_clients(self, items=None):
        """

        """

        if self.__who is None:
            message = {"message_status": "total", "number_total": len(self.__client_sockets),
                       "server_name": self.__server_name}
        else:
            if items:
                message = {"message_status": "total", "number_total": len(self.__client_sockets),
                           "server_name": self.__server_name, "who": self.__who, "items": items}
            else:
                message = {"message_status": "total", "number_total": len(self.__client_sockets),
                           "server_name": self.__server_name, "who": self.__who}
            self.__who = None
        self.__load_balance_socket.send(pickle.dumps(message))

    def eliminate_socket(self, number):
        """

        :param number:
        """

        try:
            if self.__all_details[number].get("Connected") == 1:
                if self.__all_details[number].get("Credentials") is not None:
                    self.__who = self.__all_details[number].get("Credentials")

                self.__selector.unregister(self.__all_details[number].get("Client"))
                self.__all_details[number].get("Client").close()

                self.__client_sockets.pop(number)
                self.__all_details.pop(number)

                self.__credentials.pop(number)
                self.__locations.pop(number)

                self.__data_storage.pop(number)
                self.__number_of_clients -= 1

        except Exception as e:

            print(e)
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

        if m:
            for collected in m:
                self.__item_locations.remove(collected)
                self.set_item_locations()
                print("GOT HIM")

    def update_enemies(self):
        """

        """

        m = [loc for loc in self.__enemy_locations]

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
        send_to_load_balancer = []

        for sock in self.__client_sockets:
            try:
                sock.send(pickle.dumps(["LEAVE"]))
                sock.settimeout(0.003)

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

    net_base = DatabaseManager("IPs", PARAMETERS["NET"])
    login_data_base = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])

    username_database = DatabaseManager("PlayerDetails", PARAMETERS["Users"])
    stat_data_base = DatabaseManager("IPs", PARAMETERS["STAT"])
    numbers = TheNumbers().run()

    server = Server(main_data_base, login_data_base, ips_data_base, numbers, username_database, stat_data_base, net_base)
    server.run()


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    main()
