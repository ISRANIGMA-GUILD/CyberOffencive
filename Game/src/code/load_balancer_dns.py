import socket
import netifaces


class Server:
    def __init__(self, port=1801):
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.server_socket.bind(('0.0.0.0', self.port))
        print("Server started.")

    def listen_for_clients(self):
        print("Server is listening for clients...")

        while True:
            data, client_address = self.server_socket.recvfrom(1024)
            print(f"Received discovery request from {client_address}")

            if data.decode() == "LOAD_BALANCER_DISCOVER":
                self.server_socket.sendto("LOAD_BALANCER_SERVER_FOUND".encode(), client_address)

    def get_local_ip(self):
        """

        :return:
        """

        # Get the local IP address
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                for address_info in addresses[netifaces.AF_INET]:
                    if 'addr' in address_info:
                        return address_info['addr']
        return None


if __name__ == "__main__":
    server = Server()
    print("Server IP:", server.get_local_ip())
    server.listen_for_clients()
