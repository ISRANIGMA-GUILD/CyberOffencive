import threading
import time
import math
import socket
import select
import ssl
import pickle  # Import pickle instead of json
# Define zones on the map with their boundary coordinates
zones = {
    'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
    'Zone2': {'min_x': 40320, 'max_x':  76800, 'min_y': 0, 'max_y': 19680},
    'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
    'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200}
}
LB_IP = "localhost"
LB_PORT = 12345
CERT_FILE = "path/to/lb_cert.pem"
KEY_FILE = "path/to/lb_key.pem"
# Define the servers
servers = ['Server1', 'Server2', 'Server3', 'Server4', 'ServerBuffer']


class MainServer:
    def __init__(self):
        self.servers = []  # List of registered servers
        self.lock = threading.Lock()

    def register_server(self, server):
        with self.lock:
            self.servers.append(server)

    def assign_client_to_server(self, client_coords):
        with self.lock:
            # Use load balancer to determine the server for the client
            assigned_server = load_balancer(client_coords)
            if assigned_server:
                for server in self.servers:
                    if server.name == assigned_server:
                        server.add_client(client_coords)
                        print(f"Assigned client to {assigned_server}.")
                        return
            else:
                print("Failed to assign client to any server.")

    def transfer_client(self, client, target_server):
        with self.lock:
            for server in self.servers:
                if server != target_server:
                    if server.has_capacity():
                        server.add_client(client)
                        return
            # If no server has capacity, raise an exception or handle accordingly


class Server:
    def __init__(self, name, capacity):
        self.name = name
        self.capacity = capacity
        self.clients = []
        self.lock = threading.Lock()

    def add_client(self, client):
        with self.lock:
            self.clients.append(client)

    def get_load(self):
        with self.lock:
            return len(self.clients)

    def remove_client(self, client):
        with self.lock:
            self.clients.remove(client)

    def has_capacity(self):
        with self.lock:
            return len(self.clients) < self.capacity


def euclidean_distance(coord1, coord2):
    # Calculate Euclidean distance between two coordinates
    return math.sqrt((coord1[0] - coord2[0]) ** 2 + (coord1[1] - coord2[1]) ** 2)


def get_quadrant(coords):
    x, y = coords
    if x < map_center_x:
        if y < map_center_y:
            return 1
        else:
            return 3
    else:
        if y < map_center_y:
            return 2
        else:
            return 4


def load_balancer(client_coords):
    quadrant_client = get_quadrant(client_coords)

    # Find the closest zone to the client
    min_distance = float('inf')
    closest_zone = None
    for zone, boundary in zones.items():
        zone_center = ((boundary['min_x'] + boundary['max_x']) / 2, (boundary['min_y'] + boundary['max_y']) / 2)
        distance = euclidean_distance(client_coords, zone_center)
        if distance < min_distance:
            min_distance = distance
            closest_zone = zone

    # Assign client to the server handling the closest zone
    if closest_zone:
        return closest_zone  # Use the zone name as the server name
    else:
        return None  # Unable to determine server


def start_tls_server(main_server, ip, port, certfile, keyfile):
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the IP address and port
    server_socket.bind((ip, port))

    # Listen for incoming connections
    server_socket.listen()

    print("TLS server started. Listening for incoming connections...")

    while True:
        # Accept incoming connection
        client_socket, client_address = server_socket.accept()
        print("Incoming connection from:", client_address)

        # Start a new thread to handle the client connection
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()


def handle_client(client_socket):
    # Handle TCP connection
    print("TCP connection established with client.")

    # Start TLS handshake
    try:
        # Wrap the client socket with SSL/TLS
        ssl_socket = ssl.wrap_socket(client_socket, server_side=True, certfile='server.crt', keyfile='server.key',
                                     ssl_version=ssl.PROTOCOL_TLS)

        # Perform handshake
        ssl_socket.do_handshake()
        print("TLS handshake completed successfully.")

        # TLS connection established, handle further communication
        # For example, send/receive data over the TLS connection

    except ssl.SSLError as e:
        print("TLS handshake failed:", e)

    finally:
        # Close the connection
        ssl_socket.close()


# new functions
def create_tls_server_socket(host, port, certfile, keyfile):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    tls_sock = context.wrap_socket(sock, server_side=True)
    return tls_sock


def accept_tls_connections(tls_socket):
    server_names = ["Server 1", "Server 2", "Server 3", "Server 4", "Buffer Server"]
    connections = []
    for name in server_names:
        client_socket, addr = tls_socket.accept()
        print(f"Connected to {name} from {addr}")
        client_socket.sendall(name.encode())
        connections.append((name, client_socket))
    return connections


def handle_redirections(connections):
    server_sockets = {name: sock for name, sock in connections}
    while True:
        for server_name, server_socket in server_sockets.items():
            try:
                message = server_socket.recv(1024).decode()
                if message.startswith("Redirect client"):
                    _, client_info, to_server = message.split(' to ')
                    print(f"Received redirection request from {server_name} to redirect {client_info} to {to_server}")
                    if to_server in server_sockets:
                        server_sockets[to_server].sendall(f"Handle {client_info}".encode())
                        print(f"Redirected {client_info} to {to_server}")
            except Exception as e:
                print(f"Error handling redirection: {str(e)}")


class LoadBalancer:
    def __init__(self, ip, port, certfile, keyfile):
        self.load_balancer_ip = ip
        self.load_balancer_port = port
        self.server_names = ["Server 1", "Server 2", "Server 3", "Server 4", "BufferServer"]
        self.servers = []
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.load_balancer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.load_balancer_socket.bind((self.load_balancer_ip, self.load_balancer_port))
        self.load_balancer_socket.listen()
        self.load_balancer_socket = self.context.wrap_socket(self.load_balancer_socket, server_side=True)
        self.zones = {
            'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
            'Zone2': {'min_x': 40320, 'max_x': 76800, 'min_y': 0, 'max_y': 19680},
            'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
            'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200}
        }
        print("Load balancer setup complete. Listening for server connections...")

    def accept_connections(self):
        while len(self.servers) < 5:
            connection, addr = self.load_balancer_socket.accept()
            connection = self.context.wrap_socket(connection, server_side=True)
            self.servers.append(connection)
            print(f"Connected to {addr}. Total servers connected: {len(self.servers)}")

        for index, server in enumerate(self.servers):
            server_name = self.server_names[index]
            server.send(pickle.dumps(f"Your name is {server_name}"))  # Use pickle to send data
            print(f"Assigned {server_name} to server at {server.getpeername()}")

    def determine_server(self, client_info):
        x, y = client_info['x'], client_info['y']
        for zone_name, bounds in self.zones.items():
            if bounds['min_x'] <= x <= bounds['max_x'] and bounds['min_y'] <= y <= bounds['max_y']:
                return self.servers[self.server_names.index(zone_name.replace("Zone", "Server"))]
        return self.servers[-1]  # BufferServer

    def relay_client_info(self):
        while True:
            ready_to_read, _, _ = select.select(self.servers, [], [], 0.5)
            for server in ready_to_read:
                try:
                    data = server.recv(1024)
                    if data:
                        client_info = pickle.loads(data)  # Use pickle to load data
                        target_server = self.determine_server(client_info)
                        target_server.send(pickle.dumps(client_info))  # Use pickle to send data
                        print(f"Routed client data to {target_server.getpeername()}")
                except ssl.SSLError as e:
                    print(f"SSL error with {server.getpeername()}: {e}")
                except Exception as e:
                    print(f"Error with {server.getpeername()}: {e}")

    def run(self):
        self.accept_connections()
        self.relay_client_info()


def main():
    main_server = MainServer()

    # Register servers with main server
    server1 = Server("Server1", capacity=50)
    server2 = Server("Server2", capacity=50)
    server3 = Server("Server3", capacity=50)
    server4 = Server("Server4", capacity=50)
    ServerBuffer = Server("ServerBuffer", capacity=50)
    main_server.register_server(server1)
    main_server.register_server(server2)
    main_server.register_server(server3)
    main_server.register_server(server4)
    main_server.register_server(ServerBuffer)

    lb = LoadBalancer(LB_IP, LB_PORT, CERT_FILE, KEY_FILE)
    lb.run()
    # Start TLS server
    threading.Thread(target=start_tls_server, args=(main_server, '127.0.0.1', 8443, 'server.crt', 'server.key')).start()
    tls_server_socket = create_tls_server_socket(HOST, PORT, TLS_CERT, TLS_KEY)
    connections = accept_tls_connections(tls_server_socket)
    handle_redirections(connections)
    # Main server communication
    while True:
        print("Main server (LoadBalancer) is waiting for communication from other servers.")
        time.sleep(5)  # Sleep for a while before checking for communication again


if __name__ == '__main__':
    main()
