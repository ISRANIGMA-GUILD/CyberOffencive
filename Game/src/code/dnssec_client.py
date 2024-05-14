import socket


class ServerDiscoveryClient:
    def __init__(self, port=42069):
        self.port = port

    def discover_server(self):
        print("Discovering server...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client_socket.bind(('0.0.0.0', 0))

        client_socket.sendto("DISCOVER".encode(), ('<broadcast>', self.port))
        client_socket.settimeout(5)

        try:
            while True:
                data, server_address = client_socket.recvfrom(1024)
                if data.decode() == "SERVER_FOUND":
                    print("Server found at:", server_address)
                    return server_address[0]  # Return the IP address of the server

        except socket.timeout:
            print("No server found.")
            return None


if __name__ == "__main__":
    client = ServerDiscoveryClient()
    server_ip = client.discover_server()
    print("Server IP:", server_ip)
