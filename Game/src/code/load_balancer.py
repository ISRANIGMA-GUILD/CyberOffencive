from wrapper_of_unique import *
from DatabaseCreator import *
from Cert_creators import *
from interesting_numbers import *
from clientpasswordgen import *
from login_scanner_lb import *
import os
import selectors
import pickle
import types

# Define zones on the map with their boundary coordinates
zones = {
    'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
    'Zone2': {'min_x': 40320, 'max_x': 76800, 'min_y': 0, 'max_y': 19680},
    'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
    'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200},
    'ZoneBuffer1': {'min_x1': 36481, 'max_x1': 40321, 'min_y1': 0, 'max_y1': 43200},
    'ZoneBuffer2': {'min_x2': 0, 'max_x2': 76800, 'min_y2': 19681, 'max_y2': 23519}
}

LB_IP = "0.0.0.0"
LB_PORT = 1800

NUMBER_OF_SERVERS = 2

# Define the servers
servers = ['Server1', 'Server2', 'Server3', 'Server4', 'Server5']
PARAMETERS = {"PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons'],
              "NODUP": ['Username', 'Password'], "DUP": ['Status', 'Items', 'Weapons'],
              "IPs": ["IP", "MAC"], "Users": ['Username'], "STAT": ["Status"],
              "NET": ["IP", "MAC", "Status"]}


class LoadBalancer:
    def __init__(self, ip, port, main_data_base, login_data_base, ips_data_base, username_database, stat_data_base,
                 net_base):
        self.load_balancer_ip = ip
        self.load_balancer_port = port

        self.server_names = ["Server 1", "Server 2", "Server 3", "Server 4", "Server5"]
        self.servers = []

        self.__credentials = []
        self.__new_credentials = []

        self.__credentials_server1 = []
        self.__credentials_server2 = []

        self.__credentials_server3 = []
        self.__credentials_server4 = []

        self.__credentials_server5 = []

        self.__session_users = []
        self.__weapons = []

        self.__temp_socket = EncryptUniqueServer("Secret", self.load_balancer_port, verifiers=Verifier(384).run(),
                                                 number=TheNumbers().run())
        self.__load_balancer_socket = self.__temp_socket.run()

        self.__main_data_base = main_data_base
        self.__login_data_base = login_data_base

        self.__ips_data_base = ips_data_base
        self.__username_database = username_database

        self.__stat_database = stat_data_base
        self.__net_base = net_base

        self.__banned_ips = []
        self.__banned_macs = []

        self.selector = selectors.DefaultSelector()
        self.selector.register(self.__load_balancer_socket, selectors.EVENT_READ, self.accept_new_connection)

        self.zones = {
            'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
            'Zone2': {'min_x': 40320, 'max_x': 76800, 'min_y': 0, 'max_y': 19680},
            'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
            'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200},
        }

        self.zone_buffer = {'ZoneBuffer1': {'min_x1': 36481, 'max_x1': 40321, 'min_y1': 0, 'max_y1': 43200},
                            'ZoneBuffer2': {'min_x2': 0, 'max_x2': 76800, 'min_y2': 19681, 'max_y2': 23519}}
        self.server_to_zone = {
            'Server 1': 'Zone1',
            'Server 2': 'Zone2',
            'Server 3': 'Zone3',
            'Server 4': 'Zone4',
            'Server 5': 'Zone5'
        }

        self.server_zone_map = {
            'Zone1': None,  # These will hold actual server address connections
            'Zone2': None,
            'Zone3': None,
            'Zone4': None,
            'Zone5': None
        }

        self.__number_of_clients_in_all = {
            'Server 1': 0,
            'Server 2': 0,
            'Server 3': 0,
            'Server 4': 0,
            'Server 5': 0
        }

        self.__total = 0

        self.__list_of_banned_users = []
        self.__list_of_existing_credentials = []

        self.__list_of_existing_resources = []
        self.__all_users = []
        print("Load balancer setup complete. Listening for server connections...")

    def run(self):
        """

        """
        print("NUMBER_OF_SERVERS")
        self.__list_of_existing_credentials, self.__list_of_existing_resources = self.organize_info(self.receive_info()[0], self.receive_info()[1], self.receive_info()[2])
        self.__list_of_banned_users = [[self.__list_of_existing_credentials[i][0],
                                        self.__list_of_existing_credentials[i][1],
                                        self.__list_of_existing_credentials[i][0]]
                                       for i in range(0, len(self.__list_of_existing_resources))
                                       if self.__list_of_existing_resources[i][0] == "banned"]
        while True:
            try:
                self.accept_connections()

            except KeyboardInterrupt:
                self.update_database()
                self.__load_balancer_socket.close()

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
        print(list_of_existing_credentials)
        self.__all_users = [cred[0] for cred in list_of_existing_credentials]

        return list_of_existing_credentials, list_of_existing_resources

    def accept_connections(self):
        """

        """

        try:
            events = self.selector.select(0)

            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

        except KeyboardInterrupt as e:
            print("Server will end service")
            print("e", e)
            self.update_database()

        except Exception as e:
            print("The general error", e)
            self.update_database()

    def accept_new_connection(self, sock, mask):
        """

        :param sock:
        :param mask:
        """

        print("Attempting to accept a new connection...")
        try:
            if len(self.servers) < NUMBER_OF_SERVERS:
                connection, addr = sock.accept()
                print("the", addr)

                pass_c = GetPassword(460).run()

                connection.settimeout(0.003)
                data = pickle.loads(connection.recv(1024))

                if pass_c != data[0]:
                    print("Banned the hacker")
                    connection.close()

                else:
                    connection.send(pickle.dumps([Verifier(480).run()]))

                    print(f"Connected to {addr}")
                    connection.setblocking(False)

                    self.servers.append(connection)
                    assigned_zone = self.server_names[len(self.servers) % len(self.server_names)]

                    self.server_zone_map[assigned_zone] = connection  # Map server to its zone
                    print("la")

                    self.send_server_configuration(connection, self.get_name())
                    data = types.SimpleNamespace(addr=addr, inb=b'', outb=b'')

                    if len(self.servers) < len(self.server_names):
                        # Assign server based on its connection order
                        assigned_zone = 'Zone' + str(len(self.servers) + 1)

                    else:
                        print("All zones are occupied. No more connections are expected.")
                        connection.close()
                        return

                    self.server_zone_map[assigned_zone] = {'address': addr}
                    print(f"Connection added to {assigned_zone}: {connection}")

                    print("Current state of server_zone_map:", self.server_zone_map)
                    print(self.server_zone_map[assigned_zone])

                    print("lo")
                    self.selector.register(connection, selectors.EVENT_READ, self.service_connection)

        except socket.timeout as e:
            print("No one tried to connect", e)

        except BlockingIOError as e:
            print(f"BlockingIOError: No incoming connections to accept yet. {e}")

        except Exception as e:
            print(f"Exception in accept_new_connection: {e}")

    def get_name(self):
        """

        :return:
        """

        if len(self.servers) == 1:
            print("moo")
            return "Server 1", 1

        if len(self.servers) == 2:
            return "Server 2", 2

        if len(self.servers) == 3:
            return "Server 3", 3

        if len(self.servers) == 4:
            return "Server 4", 4

        if len(self.servers) == 5:
            return "Server 5", 5

    def get_zone(self, zone):
        """

        :param zone:
        :return:
        """

        if zone == 1:
            print("moo")
            return {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680}

        if zone == 2:
            return {'min_x': 40320, 'max_x': 76800, 'min_y': 0, 'max_y': 19680}

        if zone == 3:
            return {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200}

        if zone == 4:
            return {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200}

        if zone == 5:
            return ({'min_x1': 36481, 'max_x1': 40321, 'min_y1': 0, 'max_y1': 43200},
                    {'min_x2': 0, 'max_x2': 76800, 'min_y2': 19681, 'max_y2': 23519})

    def update_client_database(self, username, password, status, items):
        """
        Insert or update client data in the database.

        :param username: Client's username
        :param password: Client's password
        :param status: Client's status
        :param items: Client's initial items
        """
        self.__username_database.insert_no_duplicates(values=[username], no_duplicate_params=["Username"])
        self.__main_data_base.set_values(['Password'], [password],
                                         ['Username'], [username])

        values = [username, password, status, items]
        params = PARAMETERS["PlayerDetails"]

        print(f"Updated database for client {username}")

    def service_connection(self, sock, mask):
        """
        get the data
        :param sock:
        :param mask:
        """

        try:
            sock.settimeout(0.003)
            recv_data = sock.recv(16000)

            if recv_data is not None:
                print("Data received:", recv_data)
                client_info = pickle.loads(recv_data)

                print("Data received:", client_info)
                if client_info['message_status'] == 'wrong_password': ###Wait the other servers already know?????
                    if client_info['server_name'] and client_info['credentials']:
                        creds = client_info['credentials']
                        server_name = client_info['server_name']
                        self.check_the_password(sock, server_name, creds)

                elif client_info['message_status'] == 'add':
                    if self.uncloned(client_info):
                        print("come on you fucking retard!")
                        self.add_client_credentials(client_info)

                        if client_info['credential'][0] in self.__all_users:
                            index = self.__list_of_existing_credentials.index(client_info['credential'])
                            message = {'message_status': 'do_add', 'items': self.__list_of_existing_resources[index]}

                        else:
                            message = {'message_status': 'do_add'}

                        print(f"sent to server{message}", self.__all_users)
                        sock.send(pickle.dumps(message))

                    elif not self.uncloned(client_info):
                        message = {'message_status': 'dont'}
                        print(f"sent to server{message}")
                        sock.send(pickle.dumps(message))

                elif client_info['message_status']:
                    if client_info['message_status'] == 'move':
                        credentials = client_info['credentials']
                        username = credentials[0]

                        password = credentials[1]  # Default password if not provided
                        status = client_info['status']  # Default status if not provided

                        if status is None:
                            status = 'idle'
                        items = client_info['items']  # Default items if not provided

                        # weapons = client_info.get('weapons', 'None')  # Default weapons if not provided
                        location = client_info['location']  # Default location if not provided
                        if username in self.__session_users:
                          #  self.__session_users.remove(username)
                          #  self.__
                            self.__credentials.append({
                                'username': username, 'password': password, 'status': status, 'items': items})
                        print("smaller or equal to", self.__session_users, self.__weapons)
                       # if len(self.__session_users) > len(self.__weapons):
                         #   self.__weapons.append(items)
                   #     self.update_client_database(username, password, status, items)
                        the_servers = [self.__credentials_server1, self.__credentials_server2,
                                       self.__credentials_server3, self.__credentials_server4,
                                       self.__credentials_server5]
                        local_user_list = list(filter(lambda x: username in x, the_servers))
                        if local_user_list:
                            stuff = local_user_list[0]
                            if client_info.get("who") in stuff:
                                local_user_list.pop(local_user_list.index(client_info.get("who")))
                        self.update_database()

                        target_server = self.determine_server(location)
                        if target_server:
                            message = {'message_status': 'move', 'ip': target_server['address'],
                                       'credential': credentials}

                            if target_server is not None:
                                print("sent to server")
                                sock.send(pickle.dumps(message))
                            else:
                                print("No appropriate server found for the given location.")

                    elif client_info['message_status'] == 'total':
                        if "who" in list(client_info.keys()):
                            if client_info.get("number_total") < self.__number_of_clients_in_all[client_info.get("server_name")]:
                                print("removing")
                                the_servers = [self.__credentials_server1, self.__credentials_server2,
                                               self.__credentials_server3, self.__credentials_server4,
                                               self.__credentials_server5]
                                local_user_list = list(filter(lambda x: client_info.get("who") in x, the_servers))[0]

                                local_user_list.pop(local_user_list.index(client_info.get("who")))
                                if 'items' in client_info.keys():
                                    self.__weapons.append(client_info.get('items'))
                                self.update_database()

                        self.__number_of_clients_in_all[client_info.get("server_name")] = client_info.get("number_total")
                        self.__total = sum(list(self.__number_of_clients_in_all.values()))
                        print(self.__total)
        # except (pickle.PickleError, KeyError) as e:
        # print("Failed to process received data:", str(e))

        except socket.timeout as e:
            print(e)

        except ssl.SSLEOFError as e:
            print("Connection closedm", e)
            print("Closing connection to", sock.getpeername())

            self.update_database()
            self.selector.unregister(sock)

            sock.close()

        except ssl.SSLError as e:
            print("Connection closedm", e)
            print("Closing connection to", sock.getpeername())

            self.update_database()
            self.selector.unregister(sock)

            sock.close()

        except EOFError as e:
            print("Connection closedn", e)
            print("Closing connection to", sock.getpeername())

            self.update_database()
            self.selector.unregister(sock)

            sock.close()

        except KeyboardInterrupt as e:
            print("Server will end service")
            print("e", e)

            self.update_database()
            self.selector.unregister(sock)

            sock.close()

        except Exception as e:
            print(f"Exception in service_connection: {e}")
            self.update_database()

    def check_the_password(self, sock, server_name, creds):
        """

        :param sock:
        :param server_name:
        """

        cred = self.get_server_credentials(server_name)
        login = Login(sock, self.__list_of_existing_credentials, self.__list_of_existing_resources, cred,
                      self.__new_credentials, len(cred)
                      , self.__list_of_banned_users, creds)

        temp, self.__credentials, self.__list_of_existing_credentials, self.__list_of_existing_resources, self.__new_credentials = (
            login.run())
        pass

    def get_server_credentials(self, server_name):
        if server_name == "Server 1":
            return self.__credentials_server1
        if server_name == "Server 2":
            return self.__credentials_server2
        if server_name == "Server 3":
            return self.__credentials_server3
        if server_name == "Server 4":
            return self.__credentials_server4
        if server_name == "Server 4":
            return self.__credentials_server5

    def uncloned(self, message):
        """

        :param message:
        :return:
        """

        the_servers = [self.__credentials_server1, self.__credentials_server2,
                       self.__credentials_server3, self.__credentials_server4,
                       self.__credentials_server5]
        print(the_servers)

        if message:
            print(message['credential'], message['server_name'])
            if message['server_name'] and message['credential']:
                if (message['credential'] not in self.__credentials_server1 and
                    message['credential'] not in self.__credentials_server2 and
                    message['credential'] not in self.__credentials_server3 and
                    message['credential'] not in self.__credentials_server4 and
                    message['credential'] not in self.__credentials_server5):

                    return True

                else:
                    return False

    def add_client_credentials(self, message):
        if message:
            if message['credential'][0] not in self.__session_users:
                self.__session_users.append(message['credential'][0])
            if message['server_name'] == 'Server 1' and message['credential']:
                self.__credentials_server1.append(message['credential'])
            if message['server_name'] == 'Server 2' and message['credential']:
                self.__credentials_server2.append(message['credential'])
            if message['server_name'] == 'Server 3' and message['credential']:
                self.__credentials_server3.append(message['credential'])
            if message['server_name'] == 'Server 4' and message['credential']:
                self.__credentials_server4.append(message['credential'])
            if message['server_name'] == 'Server 5' and message['credential']:
                self.__credentials_server5.append(message['credential'])

    def determine_server(self, client_info):
        """
        return a socket for a certain server according to the location and zone
        :param client_info:
        :return:
        """
        x = client_info[0]
        y = client_info[1]
        print(f"x is {x} y is {y} ")
        buffer_zone_1 = self.zone_buffer['ZoneBuffer1']
        buffer_zone_2 = self.zone_buffer['ZoneBuffer2']

        if (buffer_zone_1['min_x1'] <= x <= buffer_zone_1['max_x1'] and buffer_zone_1['min_y1'] <= y <= buffer_zone_1[
            'max_y1']) or \
                (buffer_zone_2['min_x2'] <= x <= buffer_zone_2['max_x2'] and buffer_zone_2['min_y2'] <= y <=
                 buffer_zone_2['max_y2']):
            print("Client assigned to buffer server based on buffer zone coordinates.")
            return self.server_zone_map['Zone5']  # Return the buffer server

        else:
            print("Client not within any buffer zones, routing to a regular server based on location.")

        print("no buffer")

        for zone_name, bounds in self.zones.items():
            print("value???", bounds)
            if (bounds[list(bounds.keys())[0]] <= x <= bounds[list(bounds.keys())[1]] and
                    bounds[list(bounds.keys())[2]] <= y <= bounds[list(bounds.keys())[3]]):
                print("yay :)")
                zone_data = self.server_zone_map[zone_name]
                if zone_data:
                    print(f"Checking zone: {zone_name}, address: {zone_data['address']}")
                    print(zone_name)
                    print(self.server_zone_map[zone_name])
                    if 'address' in list(zone_data.keys()):
                        print(f"Client located in {zone_name}, routing to server.")
                        return zone_data  # Return the socket connection to the server for this zone

                    else:
                        print(f"Server for {zone_name} is not connected.")
                        return

        print("No zone found for the client's location.")
        return

    def send_server_configuration(self, connection, data):
        print("ko")
        server_name, zone = data
        config_data = {
            'server_name': server_name,
            'zone': self.get_zone(zone)
        }
        print("po")
        serialized_data = pickle.dumps(config_data)
        print("op")
        connection.send(serialized_data)

    def update_database(self):
        """

        """
        print("HELLO DARKNESS MY FRIEND")
        for index in range(0, len(self.__new_credentials)):
            self.__username_database.insert_no_duplicates(values=[self.__new_credentials[index][0]],
                                                          no_duplicate_params=['Username'])

            self.__main_data_base.set_values(['Password'], [self.__new_credentials[index][1]],
                                             ['Username'], [self.__new_credentials[index][0]])

        print(self.__session_users, self.__weapons)
        for index in range(0, len(self.__session_users) - 1):
            if self.__weapons:
                if index < len(self.__weapons):
                    weapons = (str(self.__weapons[index]["A"]) + ", " + str(self.__weapons[index]["B"]) + ", "
                               + str(self.__weapons[index]["S"]))
                    items = (str(self.__weapons[index]["HPF"]) + ", " + str(self.__weapons[index]["EF"]) + ", " +
                             str(self.__weapons[index]["RHPF"]) + ", " + str(self.__weapons[index]["BEF"]))

                    self.__main_data_base.set_values(['Items', 'Weapons'], [items, weapons], ['Username'],
                                                     [self.__session_users[index]])

            # print(self.__main_data_base.set_values(['Username'], [self.__session_users[index]]))


def main():
    main_data_base = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])
    ips_data_base = DatabaseManager("IPs", PARAMETERS["IPs"])

    net_base = DatabaseManager("IPs", PARAMETERS["NET"])
    login_data_base = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])

    username_database = DatabaseManager("PlayerDetails", PARAMETERS["Users"])
    stat_data_base = DatabaseManager("IPs", PARAMETERS["STAT"])

    lb = LoadBalancer(LB_IP, LB_PORT, main_data_base, login_data_base, ips_data_base, username_database, stat_data_base,
                      net_base)
    lb.run()
    # Start TLS server


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    main()
