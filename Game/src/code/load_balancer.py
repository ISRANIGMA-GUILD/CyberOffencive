from server_handshake import *

# Define zones on the map with their boundary coordinates
zones = {
    'Zone1': {'min_x': 0, 'max_x': 36480, 'min_y': 0, 'max_y': 19680},
    'Zone2': {'min_x': 40320, 'max_x':  76800, 'min_y': 0, 'max_y': 19680},
    'Zone3': {'min_x': 0, 'max_x': 36480, 'min_y': 23520, 'max_y': 43200},
    'Zone4': {'min_x': 40320, 'max_x': 76800, 'min_y': 23520, 'max_y': 43200}
}

# Define the servers
servers = ['Server1', 'Server2', 'Server3', 'Server4', 'ServerBuffer']

MAP_CENTER_X = 38400
MAP_CENTER_Y = 76800

class MainServer:
    def __init__(self):
        self.servers = []  # List of registered servers
        self.ips = []

        self.lock = threading.Lock()
        self.sockets = []

        self.keys = []
        self.__server_sock = []

    def run(self):

        threading.Thread(target=self.start_tls_server, args=('0.0.0.0', 1800)).start()

        # Main server communication
        while True:
            print("Main server (LoadBalancer) is waiting for communication from other servers.")
            time.sleep(5)  # Sleep for a while before checking for communication again

    def register_server(self, server):
        """

        :param server:
        """

        with self.lock:
            self.servers.append(server)

    def assign_client_to_server(self, client_coords):
        """

        :param client_coords:
        :return:
        """

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

    def start_tls_server(self, ip, port):
        """
        Start the TLS server.
        """
        # Create a TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the IP address and port
        server_socket.bind((ip, port))

        # Listen for incoming connections
        server_socket.listen()

        print("TLS server started. Listening for incoming connections...")

        while len(self.sockets) != 5:
            # Accept incoming connection
            client_socket, client_address = server_socket.accept()
            print("Incoming connection from:", client_address)
            self.sockets.append(client_socket)

            # Start a new thread to handle the client connection
            self.start_connection_thread(client_socket, client_address)

    def handle_client(self, client_socket):
        """
        Handle the client connection.
        """
        try:
            # Start a new thread to handle the TLS handshake
            self.start_handshake_thread(client_socket)

            # Start a new thread to pass information over the TLS connection
            self.start_pass_information_thread(client_socket)

        except Exception as e:
            print(f"Error handling client: {e}")

        finally:
            # Close the TLS connection socket
            client_socket.close()

            # Remove the closed TLS connection socket from the list of sockets
            self.sockets.remove(client_socket)

    def start_handshake_thread(self, client_socket):
        """
        Start a new thread to handle the TLS handshake.
        """
        handshake_thread = threading.Thread(target=self.handle_handshake, args=(client_socket,))
        handshake_thread.start()

    def handle_handshake(self, client_socket):
        """
        Handle the TLS handshake.
        """
        try:
            the_handshake = ServerHandshake(client_socket)
            the_key = the_handshake.run()

            if not the_key:
                return

            else:
                self.keys.append(the_key)

        except KeyboardInterrupt:
            return

    def start_pass_information_thread(self, client_socket):
        """
        Start a new thread to pass information over the TLS connection.
        """
        pass_information_thread = threading.Thread(target=self.pass_information, args=(client_socket,))
        pass_information_thread.start()

    def pass_information(self, client_socket):
        """
        Pass information over the TLS connection.
        """
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                print(f"Received data: {data}")
                self.send_data(client_socket, data)
        except Exception as e:
            print(f"Error passing information: {e}")

    def start_connection_thread(self, ip, port):
        """
                Start a new thread to handle the connection try/except.
                """
        connection_thread = threading.Thread(target=self.handle_connection, args=(ip, port))
        connection_thread.start()

    def handle_connection(self, ip, port):
        """
                Handle the connection try/except.
                """
        try:
            # Create a TCP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Bind the socket to the IP address and port
            server_socket.bind((ip, port))

            # Listen for incoming connections
            server_socket.listen()

            print("TLS server started. Listening for incoming connections...")

            while len(self.sockets) != 5:
                # Accept incoming connection
                client_socket, client_address = server_socket.accept()
                print("Incoming connection from:", client_address)
                self.sockets.append(client_socket)

                # Start a new thread to handle the client connection
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()

        except Exception as e:
            print(f"Error handling connection: {e}")

    def send_data(self, client_socket, data):
        """
                        Send data over the TLS connection socket.
                        """
        try:
            client_socket.sendall(data)
        except Exception as e:
            print(f"Error sending data: {e}")


class Server:
    def __init__(self, name, capacity):
        self.name = name
        self.capacity = capacity

        self.clients = []
        self.lock = threading.Lock()

    def add_client(self, client):
        """

        :param client:
        """
        with self.lock:
            self.clients.append(client)

    def get_load(self):
        """

        :return:
        """

        with self.lock:
            return len(self.clients)

    def remove_client(self, client):
        """

        :param client:
        """
        with self.lock:
            self.clients.remove(client)

    def has_capacity(self):
        """

        :return:
        """

        with self.lock:
            return len(self.clients) < self.capacity


def euclidean_distance(coord1, coord2):
    """

    :param coord1:
    :param coord2:
    :return:
    """

    # Calculate Euclidean distance between two coordinates
    return math.sqrt((coord1[0] - coord2[0]) ** 2 + (coord1[1] - coord2[1]) ** 2)


def get_quadrant(coords):
    """

    :param coords:
    :return:
    """

    x, y = coords
    if x < MAP_CENTER_X:
        if y < MAP_CENTER_Y:
            return 1
        else:
            return 3
    else:
        if y < MAP_CENTER_Y:
            return 2
        else:
            return 4


def load_balancer(client_coords):
    """

    :param client_coords:
    :return:
    """

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


def main():
    main_server = MainServer()

    # Register servers with main server
    server1 = Server("Server1", capacity=50)
    server2 = Server("Server2", capacity=50)

    server3 = Server("Server3", capacity=50)
    server4 = Server("Server4", capacity=50)

    serverbuffer = Server("ServerBuffer", capacity=50)
    main_server.register_server(server1)

    main_server.register_server(server2)
    main_server.register_server(server3)

    main_server.register_server(server4)
    main_server.register_server(serverbuffer)

    main_server.run()
    # Start TLS server


if __name__ == '__main__':
    main()