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
    def __init__(self, ip, port, certfile, keyfile):
        self.load_balancer_ip = ip
        self.load_balancer_port = port

        self.server_names = ["Server 1", "Server 2", "Server 3", "Server 4", "BufferServer"]
        self.servers = []

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

        self.zones = {
            'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
            'Zone2': {'min_x': 40320, 'max_x': 76800, 'min_y': 0, 'max_y': 19680},
            'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
            'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200}
        }
        print("Load balancer setup complete. Listening for server connections...")

    def accept_connections(self):
        """

        """
        while True:
            events = self.selector.select(0)

            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    def accept_new_connection(self, sock, mask):
        """

        :param sock:
        """
        print("starting")
        connection, addr = sock.accept()

        print(f"Connected to {addr}")
        connection.setblocking(False)

        data = types.SimpleNamespace(addr=addr, inb=b'', outb=b'')
      #  self.selector.register(connection, selectors.EVENT_READ | selectors.EVENT_WRITE, data=data)
        self.servers.append(connection)

    def relay_client_info(self):
        """

        """
        while True:
            events = self.selector.select(timeout=None)
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
                self.selector.unregister(sock)
                sock.close()

    def run(self):
        """

        """
        self.accept_connections()
        self.relay_client_info()

    def send_server_configuration(self, server_socket, server_name, zone):
        config_data = {
            'server_name': server_name,
            'zone': self.zones[server_name]  # assuming a mapping from server names to zones
        }
        serialized_data = pickle.dumps(config_data)
        server_socket.send(serialized_data)


def main():
    lb = LoadBalancer(LB_IP, LB_PORT, CERT_FILE, KEY_FILE)
    lb.run()
    # Start TLS server


if __name__ == '__main__':
    main()