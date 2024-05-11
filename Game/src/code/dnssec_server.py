import socket
import threading
import netifaces
from zeroconf import Zeroconf, ServiceInfo


class ServerD:
    def __init__(self, port=5353):
        self.port = port
        self.server_ip = None
        self.zeroconf = Zeroconf()
        self.service_name = f"Cyber-Offensive"

    def advertise_service(self):
        desc = {"version": "1.0"}
        info = ServiceInfo(
            type_="_http._tcp.local.",
            name=self.service_name + "._http._tcp.local.",
            addresses=[socket.inet_aton(socket.gethostbyname(socket.gethostname()))],
            port=self.port,
            weight=0,
            priority=0,
            properties=desc
        )
        self.zeroconf.register_service(info)
        self.server_ip = '0.0.0.0'
        print(socket.gethostname(), netifaces.gateways()['default'][netifaces.AF_INET][0])

    def stop_advertising(self):
        self.zeroconf.unregister_all_services()
        self.zeroconf.close()

    def get_server_ip(self):
        return self.server_ip


if __name__ == "__main__":
    server = ServerD()
    advertise_thread = threading.Thread(target=server.advertise_service)
    advertise_thread.start()

    # Wait for the advertise_thread to complete and set the server IP
    advertise_thread.join()

    # Now the server IP should be set correctly
    print("Server IP:", server.get_server_ip())
    input("Press any key to stop advertising...")

    server.stop_advertising()
