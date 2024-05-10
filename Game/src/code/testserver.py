from DatabaseCreator import *
from scapy.layers.inet import *
from login import *
from wrapper_of_the_server_socks import *
from wrapper_of_the_client_socks import *
import os
import threading
import pickle
import selectors

THE_USUAL_IP = '0.0.0.0'
MY_IP = socket.gethostbyname(socket.gethostname())
MAX_MSG_LENGTH = 16000
LOCAL_HOST = '127.0.0.1'
PARAMETERS = {"PlayerDetails": ['Username', 'Password', 'Status', 'Items', 'Weapons'],
              "NODUP": ['Username', 'Password'], "DUP": ['Status', 'Items', 'Weapons'],
              "IPs": ["IP", "MAC", "Status"]}


class Server:

    def __init__(self, main_data_base, login_data_base, ips_data_base, number):
        self.__secure_socket = EncryptClient("Servers", number).run()
        self.__load_balance_socket = EncryptClient("Servers", number).run()

        self.__load_balance_ip = MY_IP  # Will soon be changed according to a mechanism
        self.__load_balance_port = 1800

        self.__main_data_base = main_data_base
        self.__login_data_base = login_data_base

        self.__ips_data_base = ips_data_base
        self.__default_port = 443

        self.__sockets = [EncryptServer("Servers", port).run() for port in [6921, 8843, 8820]]
        self.__number_of_clients = 1

        self.__banned_ips = []
        self.__banned_macs = []

        self.__list_of_banned_users = []
        self.__new_credentials = []

        self.__all_details = []
        self.__credentials = []

        self.__locations = []
        self.__chat = []

        self.__status = []
        self.__ports = []

        self.__weapon_status = []
        self.__status_frame_index = []

        self.__weapons = []
        self.__hp = []

        self.__enemy_location = []
        self.__items = []

        self.__session_users = []
        self.__to_send = []

        self.__data_to_send = []
        self.__client_sockets = []

        self.__selector = selectors.DefaultSelector()
        self.__list_of_existing_resources = []

        self.__list_of_existing_existing_credentials = []
        self.__index = 0

    def run(self):
        """

        """

        # """:TODO(Are they possible?): Check for session injection vulnerabilities """#
        # """:TODO: Add as secret verification between s -> c and c -> s"""#
        # """:TODO: Transport databases between servers at the end and updating them accordingly """#
        # """:TODO(Should the server intervene?): Check if users cheat(in speed, damage, etc.) """#
        # """:TODO(finished?): Loading screen between menu and login screens """#
        # """:TODO(Work in progress): Merge with load balancer """#
        # """:TODO(almost finished): Try-except on everything """#
        # """:TODO(Work in progress): Receive info about enemy locations, item locations """#
        # """:TODO(almost finished): Make sure server isn't bogged down due to heavy packs"""#
        # """:TODO: Show weapons when attacking"""#
        # """:TODO: Lock the database with a long and strong password"""#
        # """:TODO: Make sure clients move smoothly move between servers"""#
        # """:TODO: Create a border for clients in your server, when crossed the client is moved to another server"""#

        info, resource_info, ip_info = self.receive_info()
        self.__list_of_existing_existing_credentials, self.__list_of_existing_resources = self.organize_info(info, resource_info, ip_info)

        self.__list_of_banned_users = [[self.__list_of_existing_existing_credentials[i][0],
                                        self.__list_of_existing_existing_credentials[i][1],
                                        self.__list_of_existing_existing_credentials[i][0]]
                                       for i in range(0, len(self.__list_of_existing_resources))
                                       if self.__list_of_existing_resources[i][0] == "banned"]
        print(self.__banned_ips, self.__banned_macs, self.__list_of_existing_resources, self.__list_of_banned_users)

        print("The server will now wait for clients")
        print("Server is up and running")

        self.handle_clients()

    def receive_info(self):
        """

        :return:
        """

        main_cursor = self.__main_data_base.get_cursor()
        main_cursor.execute("SELECT Username, Password FROM PlayerDetails")

        info = main_cursor.fetchall()
        main_resource_cursor = self.__main_data_base.get_cursor()

        main_resource_cursor.execute("SELECT Status, Items, Weapons FROM PlayerDetails")
        resource_info = main_resource_cursor.fetchall()

        main_ip_cursor = self.__ips_data_base.get_cursor()
        main_ip_cursor.execute("SELECT IP, MAC FROM IPs")

        ip_info = main_ip_cursor.fetchall()

        return info, resource_info, ip_info

    def organize_info(self, info, resource_info, ip_info):
        """

        :param info:
        :param resource_info:
        :param ip_info:
        """

        list_of_existing_credentials = [vital_info for vital_info in info]
        list_of_existing_resources = [vital_resources for vital_resources in resource_info]

        self.__banned_ips = [vital_info[0] for vital_info in ip_info]
        self.__banned_macs = [vital_info[1] for vital_info in ip_info]

        return list_of_existing_credentials, list_of_existing_resources

    def connect_to_security(self):

        while True:
            try:
                self.__secure_socket.connect((LOCAL_HOST, 443))
                print("succ")

                break

            except ConnectionRefusedError:
                print("what")
                pass

            except ConnectionResetError:
                print("huh")
                pass

            except socket.error as e:
                if e.errno == errno.EADDRINUSE:
                    print("Port is already in use")

    def connect_to_load_socket(self):
        """

        """

        while True:
            try:
                self.__load_balance_socket.connect((MY_IP, 1800))
                break

            except ConnectionRefusedError:
                pass

            except ConnectionResetError:
                pass

            except OSError:
                pass

    def check_for_banned(self, client_address, number):
        """

        :param client_address:
        :param number:
        """
        print(client_address)
        if client_address[0] in self.__banned_ips or getmacbyip(client_address[0]) in self.__banned_macs:
            self.__all_details[number]["Connected"] = 1

        else:
            print("success")

    def create_server_sockets(self):
        """

        """

        try:
            if len(self.__sockets) < 3:
                port = random.choice([6921, 8843, 8820])
                sockets = EncryptServer("Servers", port).run()

                print(f"creating for clients")
                self.__sockets.append(sockets)

        except OSError:
            return

        except TypeError:
            return

        except IndexError:
            return

    def create_message(self, some_data):
        """
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """

        full_data = pickle.dumps(some_data)

        return full_data

    def handle_clients(self):
        """

        """
        self.__selector.register(self.__sockets[0], selectors.EVENT_READ, self.accept)
        self.__selector.register(self.__sockets[1], selectors.EVENT_READ, self.accept)
        self.__selector.register(self.__sockets[2], selectors.EVENT_READ, self.accept)

        while True:
            try:

                self.new_handling()

                if self.empty_server():
                    print("left2")
                    self.update_database()

                    self.__login_data_base.close_conn()
                    self.__main_data_base.close_conn()

             #       self.disconnect_from_security()
                    self.__ips_data_base.close_conn()
                    break

            #       except AttributeError:
            #       print("wait huh")
            #      pass

            except ConnectionResetError:
                print("Server will end service")
                self.update_database()

                self.__login_data_base.close_conn()
                self.__main_data_base.close_conn()

              #  self.disconnect_from_security()
                self.__ips_data_base.close_conn()

                break

            except KeyboardInterrupt:
                print("Server will end service")
                self.update_database()

                self.__login_data_base.close_conn()
                self.__main_data_base.close_conn()

              #  self.disconnect_from_security()
                self.__ips_data_base.close_conn()

                break

        print("FINISH")

    def update_credential_list(self):
        """

        """
      #  print("updating")
        if self.__number_of_clients - 1 >= len(self.__all_details) or len(self.__all_details) == 0:
          #  n = random.randint(0, 2)
            self.__all_details.append({"Credentials": None, "Sockets": None, "Client": None, "Timer": None,
                                       "Connected": 0})

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__credentials) or len(self.__credentials) == 0:
            self.__credentials.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__locations) or len(self.__locations) == 0:
            self.__locations.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__chat) or len(self.__chat) == 0:
            self.__chat.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__status) or len(self.__status) == 0:
            self.__status.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__items) or len(self.__items) == 0:
            self.__items.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__weapons) or len(self.__weapons) == 0:
            self.__weapons.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__status_frame_index) or len(self.__status_frame_index) == 0:
            self.__status_frame_index.append(None)

        else:
            pass

        if self.__number_of_clients - 1 >= len(self.__session_users) or len(self.__session_users) == 0:
            self.__session_users.append(None)

        else:
            pass

    def create_security_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []
        the_thread = threading.Thread(target=self.handle_security, args=(lock,))
        threads.append(the_thread)

        return threads

    def new_handling(self):

        events = self.__selector.select(0)

        for key, mask in events:
            self.update_credential_list()
            self.update_database()
          #  print(key.fileobj)
            callback = key.data
            callback(key.fileobj, mask)
      #  print("final", self.__index)

    def accept(self, current_socket, mask):
        """

        :param current_socket:
        :param mask:
        """

        target = list(filter(lambda person: person["Sockets"] is None and person["Credentials"] is None,
                             self.__all_details))[0]
        index = self.__all_details.index(target)

        print("pre index", index)
     #   if index != -1:
     #   current_socket.settimeout(0.1)
        connection, client_address = current_socket.accept()
        print("New client joined!", client_address)

        #   data_to_send.append((0, 0))
        self.__to_send.append((current_socket, "yay"))
        self.check_for_banned(client_address, index)

        self.__client_sockets.append(connection)

        self.__all_details[index]["Client"] = connection
        self.__all_details[index]["Sockets"] = current_socket

        self.__number_of_clients += 1
        self.print_client_sockets()

        connection.setblocking(False)
        self.__selector.register(connection, selectors.EVENT_READ, self.receive_login)

    def receive_login(self, current_socket, mask):
        """

        :param current_socket:
        :param mask:
        """

       # print(self.get_current_client_index())
        target = list(filter(lambda person: person["Client"] == current_socket and person["Credentials"] is None,
                             self.__all_details))[0]
        index = self.__all_details.index(target)
        print("indexc", index)
        try:

            current_socket.settimeout(0.5)
            data = pickle.loads(current_socket.recv(MAX_MSG_LENGTH))

            print("data", index, data, self.__all_details)
            print("start", index)

            print("please", data)
            if "EXIT" in data[0]:
                print("Connection closed", data)
                self.__all_details[index]["Connected"] = 1

                self.eliminate_socket(index)
                self.print_client_sockets()

                self.__weapons[index] = data[2]
                self.update_database()
            else:
                print("client", index)
                print(data)
                if type(data) is tuple:
                    print("well", data, index)
                    loging = Login(self.__all_details[index], self.__list_of_existing_existing_credentials,
                                   self.__list_of_existing_resources, self.__credentials, index,
                                   self.__new_credentials, self.__number_of_clients,
                                   self.__list_of_banned_users, data)

                    (self.__all_details[index], self.__credentials, list_of_existing,
                     list_of_existing_resources, self.__new_credentials,
                     self.__number_of_clients) = loging.run()
                    self.__to_send.append((current_socket, data))

                    if self.__all_details[index].get("Credentials") is not None:
                        print("yayyyy")
                        self.__session_users[index] = self.__all_details[index].get("Credentials")[0]
                        self.__selector.modify(current_socket, selectors.EVENT_READ, self.update_clients)
                #     self.__number_of_clients += 1
                # current_socket.send(pickle.dumps(["Success"]))
       # else:
            #print("logged or spmething", self.__credentials, index, self.__new_credentials)

        except socket.timeout:
            pass

        except ssl.SSLEOFError as e:
            print("Connection closed", e)
            self.__all_details[index]["Connected"] = 1

            self.eliminate_socket(index)
            self.print_client_sockets()

        except EOFError as e:
            print("Connection closed", e)
            self.__all_details[index]["Connected"] = 1

            self.eliminate_socket(index)
            self.print_client_sockets()

    def update_clients(self, current_socket, mask):
        """

        :param current_socket:
        :param mask:
        """
        target = list(filter(lambda person: person["Client"] == current_socket and person["Credentials"] is not None,
                             self.__all_details))[0]
        index = self.__all_details.index(target)
        print(self.__credentials, self.__session_users)
        try:
            current_socket.settimeout(0.01)
            data = pickle.loads(current_socket.recv(MAX_MSG_LENGTH))
            print(data)
            if "EXIT" in data[0]:
                print("Connection closed", data)
                self.__all_details[index]["Connected"] = 1

                self.eliminate_socket(index)
                self.print_client_sockets()

                self.__weapons[index] = data[2]
                self.update_database()

            elif len(self.__credentials) <= len(self.__session_users) and type(data) is not tuple:
                self.__to_send.append((current_socket, data))
                #  print("success", len(self.__client_sockets), len(data), data)

                if len(self.__client_sockets) > len(self.__data_to_send):
                    self.__data_to_send.append(data)
                    print(self.__data_to_send)
                else:
                    if len(self.__data_to_send) > 0:
                        self.__data_to_send[index] = data

                self.__locations[index] = data[0]

                if data[1] is not None and len(data[1]) > 0:
                    self.__chat[index] = data[1]

                self.__status[index] = data[2]
                self.__status_frame_index[index] = data[4]

                self.send_to_clients(self.__data_to_send, self.__to_send, index)

        except socket.timeout:
            pass

        except ssl.SSLEOFError:
            print("Connection closed", )
            self.__all_details[index]["Connected"] = 1

            self.eliminate_socket(index)
            self.print_client_sockets()

        except EOFError:
            print("Connection closed", )
            self.__all_details[index]["Connected"] = 1

            self.eliminate_socket(index)
            self.print_client_sockets()

      #  except IndexError:
        #    print("index error")
        #    self.__index = 0

    def handle_security(self, lock):
        """

        :param lock:
        :return:
        """

        with lock:
            ban_users = self.security_server_report()
            if not ban_users:
                pass

            else:
                if not self.__banned_ips and not self.__banned_macs:
                    self.__banned_ips, self.__banned_macs = ([ban_users[i][0] for i in range(0, len(ban_users))],
                                                             [ban_users[i][1] for i in range(0, len(ban_users))])
                else:
                    for i in range(0, len(ban_users)):
                        if ban_users[i][0] not in self.__banned_ips:
                            self.__banned_ips.append(ban_users[i][0])

                        if ban_users[i][1] not in self.__banned_ips:
                            self.__banned_macs.append(ban_users[i][1])

    def security_server_report(self):
        """

        """

        try:
            data = self.deconstruct_data(self.__secure_socket, 0.001)

            if not data:
                return

            else:
                decrypted_data = data

                if decrypted_data == 1:
                    self.__secure_socket.close()
                    self.__secure_socket = EncryptClient("Server", 2)

                    self.connect_to_security()
                    return

                unpacked_data = pickle.loads(decrypted_data)
                return unpacked_data

        except socket.timeout:
            return

    def send_to_clients(self, data_to_send, messages_to_send, number):
        """

        :param number:
        :param data_to_send:
        :param messages_to_send:
        """

        print("daaaaat", data_to_send)
        print("cleaned", messages_to_send)

        print(self.__all_details[number])
        eligables = list(filter(lambda person: person["Client"] is not None and person["Credentials"] is not None
                                and person != self.__all_details[number], self.__all_details))

        print(eligables, self.__all_details[number] in eligables, self.__locations[number])
        message = [self.__locations[number], self.__chat[number], self.__status[number],
                   self.__status_frame_index[number]]

        for socks in eligables:
            try:
                print("What", socks["Client"])
                socks["Client"].send(pickle.dumps(message))

            except ConnectionResetError:
                print("not  good")
                pass

            except ssl.SSLError:
                print("not  good")
                pass

    def print_client_sockets(self):
        """

        """

        for c in self.__client_sockets:
            try:
                print("\t", c.getpeername())
            except OSError as e:
                print("old client", e)

    #  except Exception:
    #  print("didnt work")
    # return

    def eliminate_socket(self, number):
        """

        :param number:
        """

        try:
            if self.__all_details[number].get("Connected") == 1:
                self.__selector.unregister(self.__all_details[number].get("Client"))
                self.__all_details[number].get("Client").close()

                self.__client_sockets.pop(number)
                self.__all_details.pop(number)

                self.__credentials.pop(number)
                self.__locations.pop(number)

                self.__number_of_clients -= 1
                self.__ports.pop(number)

                print(self.__number_of_clients, len(self.__all_details))

        except Exception:
            return

        finally:
            return

    def empty_server(self):
        """

        :return:
        """

        return self.__number_of_clients == 0

    def view_status(self, client_number):
        """

        :param client_number:
        """

        print(self.__main_data_base.find(return_params=['Status'], input_params=['Username', 'Password'],
                                         values=(self.__credentials[client_number][0],
                                                 self.__credentials[client_number][1])))

    def update_database(self):
        """

        """
        for index in range(0, len(self.__new_credentials)):
            self.__login_data_base.insert_no_duplicates(values=[self.__new_credentials[index][0],
                                                                self.__new_credentials[index][1]],
                                                        no_duplicate_params=PARAMETERS["NODUP"])

        #  print(self.__main_data_base, self.__credentials, self.__weapons,
        #       len(self.__session_users) == len(self.__weapons))

        for index in range(0, len(self.__session_users) - 1):
            if self.__weapons[index] is not None:
                weapons = str(self.__weapons[index]["G"]) + ", " + str(self.__weapons[index]["S"])
                items = (str(self.__weapons[index]["HPF"]) + ", " + str(self.__weapons[index]["EF"]) + ", " +
                         str(self.__weapons[index]["RHPF"]) + ", " + str(self.__weapons[index]["BEF"]))
                # print("Ne weapons", weapons, "Ne items", items)

                print(self.__main_data_base.set_values(['Items', 'Weapons'], [items, weapons], ['Username'],
                                                       [self.__session_users[index]]))

    def disconnect_from_security(self):
        """

        """

        try:
            message = pickle.dumps(["EXIT"])

            self.__secure_socket.send(message)
            self.__secure_socket.close()

        except ConnectionResetError:
            return

    def get_local_client_details(self):
        """

        :return:
        """

        return self.__main_data_base, self.__login_data_base, self.__ips_data_base


def main():
    """
    Main function
    """

    main_data_base = DatabaseManager("PlayerDetails", PARAMETERS["PlayerDetails"])
    ips_data_base = DatabaseManager("IPs", PARAMETERS["IPs"])

    login_data_base = DatabaseManager("PlayerDetails", PARAMETERS["NODUP"])
    server = Server(main_data_base, login_data_base, ips_data_base, 0)

    server.run()


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    main()
