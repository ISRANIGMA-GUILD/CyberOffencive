from zeroconf import Zeroconf, ServiceBrowser
import socket
import threading


class Discoverer:
    def __init__(self, service_name=None):
        self.__service_name = service_name or f"Server-{socket.gethostname()}-"  # Default to original name if not provided
        self.__resolved = threading.Event()
        self.__server_address = None
        self.__zeroconf = Zeroconf()
        self.__browser = ServiceBrowser(self.__zeroconf, "_http._tcp.local.", self, self.add_service)

    def discover_server(self):
        try:
            self.__resolved.wait(5)  # Wait until the service is resolved
        except Exception as e:
            print("Error occurred while discovering server:", e)
        finally:
            self.__zeroconf.close()
        return self.__server_address

    def add_service(self, zeroconf, type, name):
        if self.__service_name in name:
            try:
                info = zeroconf.get_service_info(type, name, timeout=5)  # Adjust the timeout value as needed
                if info:
                    self.__server_address = socket.inet_ntoa(info.addresses[0]) if info.addresses else None
                    if self.__server_address:
                        self.__resolved.set()  # Set the event to indicate that service is resolved
            except Exception as e:
                print("Error occurred while resolving service:", e)

    def update_service(self, zeroconf, type, name):
        pass  # Empty method to satisfy the requirements

    def remove_service(self, zeroconf, type, name):
        pass  # Empty method to satisfy the requirements

def main():
    discoverer = Discoverer()
    server_ip = discoverer.discover_server()
    print("Discovered server IP:", server_ip)

if __name__ == "__main__":
    main()