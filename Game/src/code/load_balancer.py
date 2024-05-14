from Cert_creators import *
import socket
import ssl
import selectors
import pickle
import types

# Define zones on the map with their boundary coordinates
zones = {
    'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
    'Zone2': {'min_x': 40320, 'max_x':  76800, 'min_y': 0, 'max_y': 19680},
    'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
    'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200}
}
LB_IP = "0.0.0.0"
LB_PORT = 1800
CERT_FILE = "Secret_Certificates\\certificate0.pem"
KEY_FILE = "Secret_Keys\\the_key0.key"
# Define the servers
servers = ['Server1', 'Server2', 'Server3', 'Server4', 'ServerBuffer']


class LoadBalancer:
<<<<<<< Updated upstream
    def __init__(self, ip, port, certfile, keyfile):
        self.load_balancer_ip = ip
        self.load_balancer_port = port
=======
    def __init__(self, ip, port):
        self.__load_balancer_ip = ip
        self.__load_balancer_port = port
>>>>>>> Stashed changes

        self.__server_names = ["Server 1", "Server 2", "Server 3", "Server 4", "BufferServer"]
        self.__servers = []

<<<<<<< Updated upstream
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=Verifier(384).run())

        self.temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.temp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.load_balancer_socket = self.context.wrap_socket(self.temp_socket, server_side=True)
        self.temp_socket.close()

        self.load_balancer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.load_balancer_socket.setblocking(False)

        self.load_balancer_socket.bind((self.load_balancer_ip, self.load_balancer_port))
        self.load_balancer_socket.listen(1)

        self.selector = selectors.DefaultSelector()
        self.selector.register(self.load_balancer_socket, selectors.EVENT_READ, self.accept_new_connection)
=======
        self.__temp_socket = EncryptUniqueServer("Secret", self.__load_balancer_port, verifiers=Verifier(384).run(),
                                                 number=TheNumbers().run())
        self.__load_balancer_socket = self.__temp_socket.run()
        self.__load_balancer_socket.setblocking(False)

        self.__selector = selectors.DefaultSelector()
        self.__selector.register(self.__load_balancer_socket, selectors.EVENT_READ,
                                 self.accept_new_connection(self.__load_balancer_socket))
>>>>>>> Stashed changes

        self.__zones = {
            'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
            'Zone2': {'min_x': 40320, 'max_x': 76800, 'min_y': 0, 'max_y': 19680},
            'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
            'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200}
        }

        self.__server_zone_map = {
            'Zone1': None,  # These will hold actual server socket connections
            'Zone2': None,
            'Zone3': None,
            'Zone4': None,
            'Buffer': None  # A buffer server for out-of-zone or overflow handling
        }
        print("Load balancer setup complete. Listening for server connections...")

    def accept_connections(self):
        """

        """
        while True:
            events = self.__selector.select(0)

            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    def accept_new_connection(self, sock):
<<<<<<< Updated upstream
        print("starting")
        new_socket, addr = sock.accept()
        print(f"Connected to {addr}")
        new_socket.setblocking(False)
        secure_socket = self.context.wrap_socket(new_socket, server_side=True)
        print(f"TLS connection established with {addr}")

        # Call send_server_configuration right after establishing the connection
        self.send_server_configuration(secure_socket, self.server_names[len(self.servers)],
                                       self.zones[self.server_names[len(self.servers)]])

        self.selector.register(secure_socket, selectors.EVENT_READ | selectors.EVENT_WRITE, data=secure_socket)
        self.servers.append(secure_socket)

    # def accept_new_connection(self, sock, mask):

        # print("starting")
        # connection, addr = sock.accept()

        #print(f"Connected to {addr}")
        connection.setblocking(False)

        # data = types.SimpleNamespace(addr=addr, inb=b'', outb=b'')
        # self.selector.register(connection, selectors.EVENT_READ | selectors.EVENT_WRITE, data=data)
        # self.servers.append(connection)
=======
        """

        :param sock:
        """
        try:
            print("starting")
            connection, addr = sock.accept()

            print(f"Connected to {addr}")
            connection.setblocking(False)
            self.__servers.append(connection)
            # data = types.SimpleNamespace(addr=addr, inb=b'', outb=b'')
            #  self.__selector.register(connection, selectors.EVENT_READ | selectors.EVENT_WRITE, data=data)
            if self.__servers:
                server_name = self.__server_names[
                    len(self.__servers) % len(self.__server_names)]  # Cycle through server names if more than defined
            else:
                server_name = self.__server_names[0]

                # Append the new server connection
            self.__servers.append(connection)

            # Send configuration to the newly connected server
            self.send_server_configuration(connection, server_name, self.__zones[server_name.replace("Server", "Zone")])

            # Register the new server for read events
            self.__selector.register(connection, selectors.EVENT_READ, self.service_connection(key, mask))

            print(f"Configuration sent to {server_name} at {addr}")
            assigned_zone = self.__server_names[len(self.__servers) % len(self.__server_names)]
            self.__server_zone_map[assigned_zone] = connection  # Map server to its zone
            print(f"Server connected and assigned to {assigned_zone} at {addr}")
        except BlockingIOError:
            pass

    def determine_server(self, client_info):
        """
        Determines which server should handle the given client based on zone information.
        :param client_info: Dictionary containing 'x' and 'y' coordinates of the client
        :return: The socket connection to the appropriate server
        """
        x, y = client_info['x'], client_info['y']
        for zone_name, bounds in self.zones.items():
            if bounds['min_x'] <= x <= bounds['max_x'] and bounds['min_y'] <= y <= bounds['max_y']:
                return self.server_zone_map[zone_name]
        return self.server_zone_map['Buffer']  # Default to buffer server if no zone matches
>>>>>>> Stashed changes

    def relay_client_info(self):
        """

        """
        while True:
            events = self.__selector.select(timeout=None)
            for key, mask in events:
                if key.data:
                    self.service_connection(key, mask)

    def service_connection(self, key, mask):
        """

        :param key:
        :param mask:
        """
        sock = key.fileobj
        data = key.data

        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(1024)
            if recv_data:
                print("Data received:", recv_data)
                client_info = pickle.loads(recv_data)

                target_server = self.determine_server(client_info)
                target_server.send(pickle.dumps(client_info))
            else:
                print("Closing connection to", data.addr)
                self.__selector.unregister(sock)
                sock.close()

    def run(self):
        """

        """
        self.accept_connections()
        self.relay_client_info()

    def send_server_configuration(self, server_socket, server_name, zone):
        config_data = {
            'server_name': server_name,
            'zone': self.__zones[server_name]  # assuming a mapping from server names to zones
        }
        serialized_data = pickle.dumps(config_data)
        server_socket.send(serialized_data)


def main():
    lb = LoadBalancer(LB_IP, LB_PORT, CERT_FILE, KEY_FILE)
    lb.run()
    # Start TLS server


if __name__ == '__main__':
    main()
