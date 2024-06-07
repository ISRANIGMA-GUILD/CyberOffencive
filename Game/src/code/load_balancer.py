from wrapper_of_unique import *
from DatabaseCreator import *
from Cert_creators import *
from interesting_numbers import *
from clientpasswordgen import *
import os
import selectors
import pickle
import types
from settings import *

# Define zones on the map with their boundary coordinates
zones = {
            'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
            'Zone2': {'min_x': 40320, 'max_x': 76800, 'min_y': 0, 'max_y': 19680},
            'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
            'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200},
            'ZoneBuffer1': {'min_x1': 36481, 'max_x1': 40321, 'min_y1': 0, 'max_y1': 43200},
            'ZoneBuffer2': {'min_x2': 0, 'max_x2': 76800, 'min_y2': 19681, 'max_y2': 23519}
}

LB_IP = "127.0.0.1"
LB_PORT = 1800

NUMBER_OF_SERVERS = 1

# Define the servers
servers = ['Server1', 'Server2', 'Server3', 'Server4', 'Server5']
PARAMETERS = {"PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons'],
              "NODUP": ['Username', 'Password'], "DUP": ['Status', 'Items', 'Weapons'],
              "IPs": ["IP", "MAC"], "Users": ['Username'], "STAT": ["Status"],
              "NET": ["IP", "MAC", "Status"]}


class LoadBalancer:
    def __init__(self, ip, port, main_data_base, login_data_base, ips_data_base, username_database, stat_data_base, net_base):
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

        self.__default_port = 443

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

        print("Load balancer setup complete. Listening for server connections...")

    def run(self):
        """

        """
        print("NUMBER_OF_SERVERS")
        while True:
            try:
                self.accept_connections()
            except KeyboardInterrupt:
                self.__load_balancer_socket.close()

    def accept_connections(self):
        try:
            print("wip")
            events = self.selector.select(timeout=None)
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)
        except KeyboardInterrupt as e:
            print("Server will end service")
            print("e", e)

    def accept_new_connection(self, sock, mask):
        """

        :param sock:
        :param mask:
        """

        print("Attempting to accept a new connection...")
        try:
            if len(self.servers) != NUMBER_OF_SERVERS:
                connection, addr = sock.accept()

                pass_c = GetPassword(460).run()

            #    sock.settimeout(0.5)
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

                    self.selector.register(connection, selectors.EVENT_READ, self.service_connection)

                    
                    if len(self.servers) < len(self.server_names):
                        # Assign server based on its connection order
                        assigned_zone = 'Zone' + str(len(self.servers) + 1)
                    else:
                        print("All zones are occupied. No more connections are expected.")
                        connection.close()
                        return
    
                    self.servers.append(connection)
                    self.server_zone_map[assigned_zone] = {'address': addr}
                    print(f"Connection added to {assigned_zone}: {connection}")
                    print("Current state of server_zone_map:", self.server_zone_map)
                    print(self.server_zone_map[assigned_zone])
                    print("lo")


        except socket.timeout as e:
            print("No one tried to connect", e)

        except BlockingIOError as e:
            print(f"BlockingIOError: No incoming connections to accept yet. {e}")
        except Exception as e:
            print(f"Exception in accept_new_connection: {e}")

    # def accept(self, sock, mask):

        # conn, addr = sock.accept()  # Should be ready

        # print('accepted', conn, 'from', addr)
        # conn.setblocking(False)
        # self.selector.register(conn, selectors.EVENT_READ, read)

    def get_name(self):
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

        #  if mask & selectors.EVENT_READ:
        try:
            sock.settimeout(TIMEOUT_TIME)
            recv_data = sock.recv(16000)

            if recv_data is not None:
                print("Data received:", recv_data)
                client_info = pickle.loads(recv_data)
                print("Data received:", client_info)
                if client_info['message_status']:
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

                        self.__session_users.append(username)
                        self.__credentials.append({
                            'username': username, 'password': password, 'status': status, 'items': items})

                        self.update_client_database(username, password, status, items)
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
                    elif client_info['message_status'] == 'add':
                        if not self.check_if_exist_on_another_server(client_info):
                            self.add_client_credentials(client_info)
                            message = {'message_status': 'do_add'}
                            print(f"sent to server{message}")
                            sock.send(pickle.dumps(message))
                        else:
                            message = {'message_status': 'dont'}
                            print(f"sent to server{message}")
                            sock.send(pickle.dumps(message))


   #     except (pickle.PickleError, KeyError) as e:
            #print("Failed to process received data:", str(e))

        except socket.timeout as e:
            print(e)

        except ssl.SSLEOFError as e:
            print("Connection closedm", e)
            print("Closing connection to", sock.getpeername())

            self.selector.unregister(sock)
            sock.close()

        except ssl.SSLError as e:
            print("Connection closedm", e)
            print("Closing connection to", sock.getpeername())

            self.selector.unregister(sock)
            sock.close()

        except EOFError as e:
            print("Connection closedn", e)
            print("Closing connection to", sock.getpeername())

        except KeyboardInterrupt as e:
            print("Server will end service")
            print("e", e)

          #  self.selector.unregister(sock)
         #   sock.close()
        except Exception as e:
            print(f"Exception in service_connection: {e}")

    def check_if_exist_on_another_server(self, message):
        if message:
            if message['server_name'] and message['credential']:
                for cred in self.__credentials_server1:
                    if cred == message['credential']:
                        if message['server_name'] == 'Server 1':
                            return False
                        else:
                            return True

                for cred in self.__credentials_server2:
                    if cred == message['credential']:
                        if message['server_name'] == 'Server 2':
                            return False
                        else:
                            return True

                for cred in self.__credentials_server3:
                    if cred == message['credential']:
                        if message['server_name'] == 'Server 3':
                            return False
                        else:
                            return True

                for cred in self.__credentials_server4:
                    if cred == message['credential']:
                        if message['server_name'] == 'Server 4':
                            return False
                        else:
                            return True

                for cred in self.__credentials_server5:
                    if cred == message['credential']:
                        if message['server_name'] == 'Server 5':
                            return False
                        else:
                            return True

    def add_client_credentials(self, message):
        if message:
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
        for index in range(0, len(self.__new_credentials)):
            self.__username_database.insert_no_duplicates(values=[self.__new_credentials[index][0]],
                                                          no_duplicate_params=['Username'])

            self.__main_data_base.set_values(['Password'], [self.__new_credentials[index][1]],
                                             ['Username'], [self.__new_credentials[index][0]])

        print(self.__session_users, self.__weapons)
        for index in range(0, len(self.__session_users) - 1):
            if self.__weapons:
                if self.__weapons[index] is not None:
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

    login_data_base = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])
    username_database = DatabaseManager("PlayerDetails", PARAMETERS["Users"])
    stat_data_base = DatabaseManager("IPs", PARAMETERS["STAT"])
    net_base = DatabaseManager("IPs", PARAMETERS["NET"])

    lb = LoadBalancer(LB_IP, LB_PORT, main_data_base, login_data_base, ips_data_base, username_database, stat_data_base,
                      net_base)
    lb.run()
    # Start TLS server

if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    main()