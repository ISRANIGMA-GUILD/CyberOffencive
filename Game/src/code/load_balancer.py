from wrapper_of_unique import *
from DatabaseCreator import *
from Cert_creators import *
from interesting_numbers import *
from clientpasswordgen import *
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
            'ZoneBuffer2': {'min_x2': 0, 'max_x2': 19680, 'min_y2': 19681, 'max_y2': 23519}
}
LB_IP = "127.0.0.1"
LB_PORT = 1800

NUMBER_OF_SERVERS = 2

# Define the servers
servers = ['Server1', 'Server2', 'Server3', 'Server4', 'Server5']
PARAMETERS = {"PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons'],
              "NODUP": ['Username', 'Password'], "DUP": ['Status', 'Items', 'Weapons'],
              "IPs": ["IP", "MAC", "Status"]}


class LoadBalancer:
    def __init__(self, ip, port, main_data_base, login_data_base, ips_data_base):
        self.load_balancer_ip = ip
        self.load_balancer_port = port

        self.server_names = ["Server 1", "Server 2", "Server 3", "Server 4", "Server5"]
        self.servers = []

        self.__credentials = []

        self.__session_users = []

        self.__weapons = []

        self.__temp_socket = EncryptUniqueServer("Secret", self.load_balancer_port, verifiers=Verifier(384).run(),
                                                 number=TheNumbers().run())
        self.__load_balancer_socket = self.__temp_socket.run()

        self.__main_data_base = main_data_base
        self.__login_data_base = login_data_base

        self.__ips_data_base = ips_data_base
        self.__default_port = 443

        self.selector = selectors.DefaultSelector()
        self.selector.register(self.__load_balancer_socket, selectors.EVENT_READ, self.accept_new_connection)

        self.zones = {
            'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
            'Zone2': {'min_x': 40320, 'max_x': 76800, 'min_y': 0, 'max_y': 19680},
            'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
            'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200},
            'ZoneBuffer1': {'min_x1': 36481, 'max_x1': 40321, 'min_y1': 0, 'max_y1': 43200},
            'ZoneBuffer2': {'min_x2': 0, 'max_x2': 19680, 'min_y2': 19681, 'max_y2': 23519}
        }
        self.server_zone_map = {
            'Zone1': None,  # These will hold actual server socket connections
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
        while len(self.servers) != NUMBER_OF_SERVERS:
            self.accept_new_connection(self.__load_balancer_socket)
        while True:
            self.accept_connections()

    def accept_connections(self):

        print("wip")
        events = self.selector.select(timeout=None)

        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)

    def accept_new_connection(self, sock):
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
                    {'min_x2': 0, 'max_x2': 19680, 'min_y2': 19681, 'max_y2': 23519})

    def relay_client_info(self):
        """

        """

        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data:
                    callback = key.data
                    callback(key.fileobj, mask)

    def update_client_database(self, username, password, status, items, weapons):
        """
        Insert or update client data in the database.

        :param username: Client's username
        :param password: Client's password
        :param status: Client's status
        :param items: Client's initial items
        :param weapons: Client's initial weapons
        """
        self.__login_data_base.insert_no_duplicates(values=[username, password], no_duplicate_params=["Username"])

        values = [username, password, status, items, weapons]
        params = PARAMETERS["PlayerDetails"]
        self.__main_data_base.insert_no_duplicates(values=values, no_duplicate_params=["Username"])

        print(f"Updated database for client {username}")

    def service_connection(self, sock, mask):
        """
        get the data
        :param sock:
        :param mask:
        """

      #  if mask & selectors.EVENT_READ:
        try:
            sock.settimeout(0.05)
            recv_data = sock.recv(1024)

            if recv_data is not None:
                print("Data received:", recv_data)
                client_info = pickle.loads(recv_data)

                username = client_info.get('username')
                password = client_info.get('password', 'defaultPassword')  # Default password if not provided
                status = client_info.get('status', 'Active')  # Default status if not provided
                items = client_info.get('items', 'None')  # Default items if not provided
                weapons = client_info.get('weapons', 'None')  # Default weapons if not provided
                location = client_info.get('location', {'x': 0, 'y': 0})  # Default location if not provided

                self.__session_users.append(username)
                self.__credentials.append({
                    'username': username, 'password': password, 'status': status, 'items': items, 'weapons': weapons
                })

                self.update_client_database(username, password, status, items, weapons)

                target_server = self.determine_server(location)
                if target_server:
                    target_server.send(pickle.dumps(client_info))
                else:
                    print("No appropriate server found for the given location.")

        except (pickle.PickleError, KeyError) as e:
            print("Failed to process received data:", str(e))

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

            self.selector.unregister(sock)
            sock.close()

    def determine_server(self, client_info):
        """
        return a socket for a certain server according to the location and zone
        :param client_info:
        :return:
        """
        x, y = client_info['x'], client_info['y']
        buffer_zone_1 = self.zones[ZoneBuffer1]
        buffer_zone_2 = self.zones[ZoneBuffer1]
        buffer_zone_1 = self.zones['ZoneBuffer1']
        buffer_zone_2 = self.zones['ZoneBuffer1']

        if (self.zones['min_x'] <= x <= buffer_zone_1['max_x'] and buffer_zone_1['min_y'] <= y <= buffer_zone_1[
            'max_y']) or \
                (buffer_zone_2['min_x'] <= x <= buffer_zone_2['max_x'] and buffer_zone_2['min_y'] <= y <= buffer_zone_2[
                    'max_y']):
            print("Client assigned to buffer server based on buffer zone coordinates.")
            return self.server_zone_map[self.__server_name]  # Return the buffer server

            return self.server_zone_map['Zone5']  # Return the buffer server

        else:
            print("Client not within any buffer zones, routing to a regular server based on location.")

        for zone_name, bounds in self.zones.items():
            if bounds['min_x'] <= x <= bounds['max_x'] and bounds['min_y'] <= y <= bounds['max_y']:
                return self.server_zone_map[zone_name]

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
            print(self.__login_data_base.insert_no_duplicates(values=[self.__new_credentials[index][0]],
                                                              no_duplicate_params=['Username']))
            print(self.__login_data_base.set_values(['Password'], [self.__new_credentials[index][1]], ['Username'],
                                                    [self.__new_credentials[index][0]]))

        print(self.__new_credentials)
        if len(self.__new_credentials) > 0:
            print(self.__new_credentials[0])

        for index in range(0, len(self.__new_credentials)):
            print(self.__login_data_base.insert_no_duplicates
                  (values=[self.__new_credentials[index][0],
                           self.__new_credentials[index][1]],
                   no_duplicate_params=PARAMETERS["NODUP"]))

        # for index in range(0, len(self.__session_users) - 1):
            # if self.__weapons[index] is not None:
                # weapons = (str(self.__weapons[index]["A"]) + ", " + str(self.__weapons[index]["B"]) +
                           # ", " + str(self.__weapons[index]["S"]))
                # items = (str(self.__weapons[index]["HPF"]) + ", " + str(self.__weapons[index]["EF"]) +
                         # ", " + str(self.__weapons[index]["RHPF"]) + ", " + str(self.__weapons[index]["BEF"]))

                # print(self.__main_data_base.set_values(['Items', 'Weapons'], [items, weapons],
                                                       # ['Username'], [self.__session_users[index]]))


def main():
    main_data_base = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])
    ips_data_base = DatabaseManager("IPs", PARAMETERS["IPs"])

    login_data_base = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])

    lb = LoadBalancer(LB_IP, LB_PORT, main_data_base, login_data_base, ips_data_base)
    lb.run()
    # Start TLS server


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    main()