import socket
import ssl

from DatabaseCreator import *
from scapy.layers.inet import *
from login import *
from wrapper_of_the_server_socks import *
from wrapper_of_the_client_socks import *
import os
import threading
import pickle
from selector import *

SYN = 2
ACK = 16
THE_USUAL_IP = '0.0.0.0'
MY_IP = socket.gethostbyname(socket.gethostname())
MAX_MSG_LENGTH = 1024
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
        self.__credentials = {}

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

    def run(self):
        """

        """

        # """:TODO(Are they possible?): Check for session injection vulnerabilities """#
        # """:TODO: Transport databases between servers at the end and updating them accordingly """#
        # """:TODO(Should the server intervene?): Check if users cheat(in speed, damage, etc.) """#
        # """:TODO: Loading screen between menu and login screens """#
        # """:TODO(Work in progress): Merge with load balancer """#
        # """:TODO(almost finished): Try-except on everything """#
        # """:TODO(Work in progress): Receive info about enemy locations, item locations """#
        # """:TODO(almost finished): Make sure server isn't bogged down due to heavy packs"""#
        # """:TODO: Show weapons when attacking"""#
        # """:TODO(almost finished): Make sure nothing appears in terminal (including chat)"""#
        # """:TODO(almost finished): Make sure when player exits the server wont miss any info"""#
        # """:TODO: Guns"""#
        print("hj;l;;")
        info, resource_info, ip_info = self.receive_info()
        list_of_existing_credentials, list_of_existing_resources = self.organize_info(info, resource_info, ip_info)
        print("hj;lwwww;")
        self.__list_of_banned_users = [[list_of_existing_credentials[i][0], list_of_existing_credentials[i][1],
                                        list_of_existing_resources[i][0]]
                                       for i in range(0, len(list_of_existing_resources))
                                       if list_of_existing_resources[i][0] == "banned"]
        print(self.__banned_ips, self.__banned_macs, list_of_existing_resources, self.__list_of_banned_users)

        print("The server will now wait for clients")

        print("Server is up and running")
        self.handle_clients(list_of_existing_credentials, list_of_existing_resources)

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

    def check_for_banned(self, connection, client_address, number):
        """

        :param connection:
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

    def handle_clients(self, list_of_existing, list_of_existing_resources):
        """

        :param security_lock:
        :param lock:
        :param list_of_existing:
        :param list_of_existing_resources:
        """

        while True:
            try:
                #  print("con")
                self.update_credential_list()
              #  print("updating")
                self.update_database()

                # selector_threads = self.create_selector_threads(lock)
                self.start_handling(list_of_existing, list_of_existing_resources)

                if self.empty_server():
                    print("left2")
                    self.update_database()
                    self.__login_data_base.close_conn()
                    self.__main_data_base.close_conn()

                    self.disconnect_from_security()
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

                self.disconnect_from_security()
                self.__ips_data_base.close_conn()

                break

            except KeyboardInterrupt:
                print("Server will end service")
                self.update_database()

                self.__login_data_base.close_conn()
                self.__main_data_base.close_conn()

                self.disconnect_from_security()
                self.__ips_data_base.close_conn()

                break

        print("FINISH")

    def update_credential_list(self):
        """

        """

        if self.__number_of_clients - 1 >= len(self.__all_details) or len(self.__all_details) == 0:
            n = random.randint(0, 2)
            self.__all_details.append({"Credentials": None, "Sockets": self.__sockets[n], "Client": None, "Timer": None,
                                       "Connected": 0, "Port": 0})

        else:
            pass

        self.__credentials[str(self.__number_of_clients - 1)] = None

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

    def start_handling(self, list_of_existing, list_of_existing_resources):
        """

        :param list_of_existing_resources:
        :param list_of_existing:
        :param security_thread:
        :param disconnect_threads:
        """
        #   print("hllo??????????")
        servers = self.__sockets
        rlist, wlist, xlist = select.select(servers + self.__client_sockets, self.__client_sockets, [], 0.7)
        index = 0
       # print("did credentials update??", self.__credentials)
        for current_socket in rlist:
        #    print(rlist, "\nsock?", current_socket, self.__client_sockets)
      #      print("client", index)
            if current_socket in servers:
                current_socket.settimeout(0.1)
                connection, client_address = current_socket.accept()
                print("New client joined!", client_address)

                #   data_to_send.append((0, 0))
                self.__to_send.append((current_socket, "yay"))
                self.check_for_banned(connection, client_address, index)

                self.eliminate_socket(index)
                self.__client_sockets.append(connection)
                self.__all_details[index]["Client"] = connection

                self.__number_of_clients += 1
                self.print_client_sockets()

            else:
              #  print("index", n)
                try:
                    if (self.__all_details[index].get("Credentials") is None and
                            self.__all_details[index].get("Client") is not None):
                        current_socket.settimeout(0.1)
                        data = pickle.loads(current_socket.recv(16000))
                        if "EXIT" in data[0]:
                            print("Connection closed", data)
                            self.__client_sockets.remove(current_socket)

                            current_socket.close()
                            self.__number_of_clients -= 1
                            self.print_client_sockets()
                          #  print("stuff", self.__weapons, self.__items)
                            self.__weapons[index] = data[2]
                            self.update_database()
                        else:
                            print("client", index)
                            print(data)
                            if type(data) is tuple:
                             #   print("well", data)
                                loging = Login(self.__all_details[index], list_of_existing, list_of_existing_resources,
                                               self.__credentials, index, self.__new_credentials, self.__number_of_clients,
                                               self.__list_of_banned_users, data)

                                (self.__all_details[index], self.__credentials, list_of_existing,
                                 list_of_existing_resources,
                                 self.__new_credentials, self.__number_of_clients) = loging.run()
                                self.__to_send.append((current_socket, data))

                                if self.__all_details[index].get("Credentials") is not None:
                                #    print("yayyyy")
                                    self.__session_users[index] = self.__all_details[index].get("Credentials")[0]
                            #    current_socket.send(pickle.dumps(["Success"]))

                    if (self.__all_details[index].get("Credentials") is not None and
                            self.__all_details[index].get("Client") is not None):
                        current_socket.settimeout(0.01)
                        data = pickle.loads(current_socket.recv(16000))
                        if "EXIT" in data[0]:
                            print("Connection closed", data)
                            self.__client_sockets.remove(current_socket)

                            current_socket.close()
                            self.__number_of_clients -= 1
                            self.print_client_sockets()
                            print("stuff", self.__weapons, self.__items)
                            self.__weapons[index] = data[2]
                            #self.__items[n] = [data[2]['HPF'], data[2]['EF'], data[2]['RHPF'], data[2]['BEF']]
                            self.update_database()

                        elif index <= len(self.__session_users) and type(data) is not tuple:
                            self.__to_send.append((current_socket, data))
                            print("success", len(self.__client_sockets), len(data), data)

                            if len(self.__client_sockets) > len(self.__data_to_send):
                                self.__data_to_send.append(data)
                            else:
                                if len(self.__data_to_send) > 0:
                                    self.__data_to_send[index] = data

                            self.__locations[index] = data[0]
                         #   print("int?", data[1])
                            if data[1] is not None and len(data[1]) > 0:
                                self.__chat[index] = data[1]
                            #      print(self.__chat, the_data[1])

                            self.__status[index] = data[2]
                            self.__status_frame_index[index] = data[4]

                            self.send_to_clients(wlist, self.__data_to_send, self.__to_send, index)

                except socket.timeout:
                    pass

                except ssl.SSLEOFError:
                    print("Connection closed", )
                    self.__client_sockets.remove(current_socket)

                    current_socket.close()
                    self.print_client_sockets()

                except EOFError:
                    print("Connection closed", )
                    self.__client_sockets.remove(current_socket)

                    current_socket.close()
                    self.print_client_sockets()

                index += 1

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

    def send_to_clients(self, wlist, data_to_send, messages_to_send, number):
        """

        :param wlist:
        :param data_to_send:
        :param messages_to_send:
        """
        print("daaaaat", data_to_send, messages_to_send)
        for socks in self.__client_sockets:
            current_socket = socks
         #   index = self.__client_sockets.index(current_socket)

        #    data = data_to_send[index]
         #  messages = messages_to_send[index]

            print(self.__locations, self.__chat, self.__status, self.__weapons, self.__status_frame_index)

            if current_socket in wlist:
                if (self.__locations is not None and self.__all_details[number].get("Client") is not None and
                        self.__all_details[number].get("Credentials") is not None):
                    try:
                        local_locations = self.__locations.copy()
                        local_locations.pop(number)
                        local_locations = [message for message in local_locations if message is not None]

                        local_messages = self.__chat.copy()
                        #    local_messages.pop(number)
                        local_messages = [f'{self.__session_users[i]}: {local_messages[i]}'
                                          for i in range(0, len(local_messages)) if local_messages[i] is not None
                                          and len(local_messages[i]) != 0]

                        local_statuses = self.__status.copy()
                        local_statuses.pop(number)
                        local_statuses = [message for message in local_statuses if message is not None]

                        local_weapons = self.__weapons.copy()
                        #   print("the weapons", local_weapons)
                        local_weapons.pop(number)

                        local_f_indexes = self.__status_frame_index.copy()
                        local_f_indexes.pop(number)
                        local_f_indexes = [message for message in local_f_indexes if message is not None]

                        list_data = local_locations, local_messages, local_statuses, local_f_indexes
                        print(list_data, len(list_data), list_data[0])

                        for i in range(0, len(list_data)):
                            if not list_data[0] and not list_data[1] and not list_data[2] and not list_data[3]:
                                pass

                            else:
                                data_of_one = list_data[0][i], list_data[1][i], list_data[2][i], list_data[3][i]
                                byte_data = self.create_message(data_of_one)
                                current_socket.send(byte_data)

                    except ConnectionResetError:
                        print("not  good")
                        pass

    def print_client_sockets(self):
        """

        @param client_sockets:
        """

        for c in self.__client_sockets:
            print("\t", c.getpeername())

    #  except Exception:
    #  print("didnt work")
    # return

    def eliminate_socket(self, number):
        """

        :param lock:
        :param number:
        """


        try:
            if self.__all_details[number].get("Connected") == 1:
                self.__all_details[number].get("Client").close()
                self.__all_details.pop(number)

                self.__credentials[str(number)] = None
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
                                         values=(self.__credentials[str(client_number)][0],
                                                 self.__credentials[str(client_number)][1])))

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
