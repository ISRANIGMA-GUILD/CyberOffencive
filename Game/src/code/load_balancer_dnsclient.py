import socket
import configparser
import os


class ServerDiscoveryClient:
    def __init__(self, port=1801):
        self.port = port

    def discover_server(self):
        print("Discovering server...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client_socket.bind(('0.0.0.0', 0))

        client_socket.sendto("LOAD_BALANCER_DISCOVER".encode(), ('<broadcast>', self.port))
        client_socket.settimeout(5)

        try:
            while True:
                data, server_address = client_socket.recvfrom(1024)
                if data.decode() == "LOAD_BALANCER_SERVER_FOUND":
                    print("Server found at:", server_address)
                    return server_address[0]  # Return the IP address of the server

        except socket.timeout:
            print("No server found.")
            return None
        
def update_docker_compose(server_ip):
    # Define the path to your docker-compose.yml file (replace with your actual path)
    docker_compose_file = "../../../docker-compose.yml"

    try:
        # Attempt to open and read the docker-compose.yml file
        with open(docker_compose_file, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: {docker_compose_file} not found.")
        return
    except IOError as e:
        print(f"Error reading {docker_compose_file}: {e}")
        return

    # Check if the file is empty
    if not content.strip():
        print(f"Error: {docker_compose_file} is empty.")
        return

    # Attempt to update the environment variable in the YAML content
    try:
        updated_content = content.replace('LOAD_BALANCER_IP=load_balancer', f'LOAD_BALANCER_IP={server_ip}', 1)
    except Exception as e:
        print(f"Error updating {docker_compose_file}: {e}")
        return

    # Write the updated content back to the file
    try:
        with open(docker_compose_file, 'w') as f:
            print(updated_content)
            f.write(updated_content)

        print(f"Updated LOAD_BALANCER_IP in {docker_compose_file}")

    except IOError as e:
        print(f"Error writing to {docker_compose_file}: {e}")
        return


if __name__ == "__main__":
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    client = ServerDiscoveryClient()
    server_ip = client.discover_server()

    update_docker_compose(server_ip)
    print("Server IP:", server_ip)
