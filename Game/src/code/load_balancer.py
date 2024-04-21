import threading
import time
import math
import socket
import ssl

# Define zones on the map with their boundary coordinates
zones = {
    'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
    'Zone2': {'min_x': 40320, 'max_x':  76800, 'min_y': 0, 'max_y': 19680},
    'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
    'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200}
}

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
        """

        :param client:
        :param target_server:
        :return:
        """

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
    """

    :param coords:
    :return:
    """

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

    # Start TLS server
    threading.Thread(target=start_tls_server, args=(main_server, '127.0.0.1', 8443, 'server.crt', 'server.key')).start()

    # Main server communication
    while True:
        print("Main server (LoadBalancer) is waiting for communication from other servers.")
        time.sleep(5)  # Sleep for a while before checking for communication again


if __name__ == '__main__':
    main()