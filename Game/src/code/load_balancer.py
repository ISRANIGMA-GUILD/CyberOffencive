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
    'Zone5': {'min_x': 36481, 'max_x': 40320, 'min_y': 19680, 'max_y': 36480}
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
            'ZoneBuffer1': {'min_x1': 1458, 'max_x1': 2187, 'min_y1': 0, 'max_y1': 3200},
            'ZoneBuffer2': {'min_x2': 0, 'max_x2': 3648, 'min_y2': 1281, 'max_y2': 1919}
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
        while len(self.servers) != NUMBER_OF_SERVERS:
            self.accept_new_connection(self.__load_balancer_socket)
        while True:
            self.accept_connections()
            self.relay_client_info()

    def accept_connections(self):
        print("wip")
        while True:
            events = self.selector.select(0)
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    def accept_new_connection(self, sock):
        print("Attempting to accept a new connection...")
        try:
            connection, addr = sock.accept()

            print(f"Connected to {addr}")
            connection.setblocking(False)

            self.servers.append(connection)
            assigned_zone = self.server_names[len(self.servers) % len(self.server_names)]

            self.server_zone_map[assigned_zone] = connection  # Map server to its zone
            print("la")

            self.send_server_configuration(connection, self.get_name())
            data = types.SimpleNamespace(addr=addr, inb=b'', outb=b'')

            self.selector.register(connection, selectors.EVENT_READ, self.service_connection)
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

    @staticmethod
    def get_zone(zone):
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
            return ({'min_x1': 1458, 'max_x1': 2187, 'min_y1': 0, 'max_y1': 3200},
                    {'min_x2': 0, 'max_x2': 3648, 'min_y2': 1281, 'max_y2': 1919})


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
        try:
            if mask & selectors.EVENT_READ:
                sock.settimeout(0.01)
                recv_data = sock.recv(1024)
                if recv_data:
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

                else:
                    pass
                    # print("Closing connection to", data.addr)
                    # self.selector.unregister(sock)
                    # sock.close()
        except (pickle.PickleError, KeyError) as e:
            print("Failed to process received data:", str(e))

        except socket.timeout:
            pass

    def determine_server(self, client_info):
        """
        return a socket for a certain server according to the location and zone
        :param client_info:
        :return:
        """
        x, y = client_info['x'], client_info['y']
        buffer_zone_1 = self.zones[ZoneBuffer1]
        buffer_zone_2 = self.zones[ZoneBuffer1]
        if (self.zones['min_x'] <= x <= buffer_zone_1['max_x'] and buffer_zone_1['min_y'] <= y <= buffer_zone_1[
            'max_y']) or \
                (buffer_zone_2['min_x'] <= x <= buffer_zone_2['max_x'] and buffer_zone_2['min_y'] <= y <= buffer_zone_2[
                    'max_y']):
            print("Client assigned to buffer server based on buffer zone coordinates.")
            return self.server_zone_map[self.__server_name]  # Return the buffer server
        else:
            print("Client not within any buffer zones, routing to a regular server based on location.")

        for zone_name, bounds in self.zones.items():
            if bounds['min_x'] <= x <= bounds['max_x'] and bounds['min_y'] <= y <= bounds['max_y']:
                return self.server_zone_map[zone_name]

    def send_server_configuration(self, server_socket, data):
        print("ko")
        server_name, zone = data
        config_data = {
            'server_name': server_name,
            'zone': self.get_zone(zone)
        }
        print("po")
        serialized_data = pickle.dumps(config_data)
        print("op")
        server_socket.send(serialized_data)

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

        for index in range(0, len(self.__session_users) - 1):
            if self.__weapons[index] is not None:
                weapons = (str(self.__weapons[index]["A"]) + ", " + str(self.__weapons[index]["B"]) +
                           ", " + str(self.__weapons[index]["S"]))
                items = (str(self.__weapons[index]["HPF"]) + ", " + str(self.__weapons[index]["EF"]) +
                         ", " + str(self.__weapons[index]["RHPF"]) + ", " + str(self.__weapons[index]["BEF"]))

                print(self.__main_data_base.set_values(['Items', 'Weapons'], [items, weapons],
                                                       ['Username'], [self.__session_users[index]]))

    def insert_no_duplicates(self, values, no_duplicate_params):
        """
        Insert a record into the database ensuring there are no duplicates based on certain parameters.

        :param values: List of values corresponding to the database schema
        :param no_duplicate_params: List of parameters to check for duplication
        """
        try:
            with self.connection.cursor() as cursor:
                columns = ', '.join(PARAMETERS["PlayerDetails"])
                placeholders = ', '.join(['%s'] * len(values))
                query = (f"INSERT INTO PlayerDetails ({columns}) SELECT {placeholders}"
                         f" WHERE NOT EXISTS (SELECT 1 FROM PlayerDetails WHERE Username=%s)")
                cursor.execute(query, values + [values[PARAMETERS["PlayerDetails"].index("Username")]])
                self.connection.commit()
        except Exception as e:
            print("Database error:", e)


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
