import random
import socket
from DatabaseCreator import *
from scapy.layers.inet import *
from login import *
from wrapper_of_the_server_socks import *
from wrapper_of_the_client_socks import *
import os
import threading
import pickle
import ssl

SYN = 2
ACK = 16
THE_USUAL_IP = '0.0.0.0'
MY_IP = conf.route.route('0.0.0.0')[1]
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


        info, resource_info, ip_info = self.receive_info()
        list_of_existing_credentials, list_of_existing_resources = self.organize_info(info, resource_info, ip_info)

        self.__list_of_banned_users = [[list_of_existing_credentials[i][0], list_of_existing_credentials[i][1],
                                        list_of_existing_resources[i][0]]
                                       for i in range(0, len(list_of_existing_resources))
                                       if list_of_existing_resources[i][0] == "banned"]
        print(self.__banned_ips, self.__banned_macs, list_of_existing_resources, self.__list_of_banned_users)

     #   self.create_security_context()
        # self.connect_to_load_socket()

        print("The server will now wait for clients")

        the_lock = threading.Lock()
        login_lock = threading.Lock()

        modification_lock = threading.Lock()
        security_lock = threading.Lock()

        print("Server is up and running")
        self.handle_clients(the_lock, login_lock, modification_lock, security_lock,
                            list_of_existing_credentials, list_of_existing_resources)

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

    def deconstruct_data(self, the_client_socket, timer):
        """
         Dissect the data received from the server
        :param the_client_socket: The client socket
        :return: The data iv, data and tag
        """
        try:
            the_client_socket.settimeout(timer)
            data_pack = the_client_socket.recv(73)

            if not data_pack:
                return

            else:
                try:
                    data = pickle.loads(data_pack)
                    return data

                except IndexError:
                    pass
            return

        except struct.error:
            print("dont")
            return

        except socket.timeout:
            return

        except OSError:
            return

        except ConnectionResetError:
            print("reconnect to security")
            return

    def handle_clients(self, the_lock, login_lock, security_lock, modification_lock, list_of_existing,
                       list_of_existing_resources):
        """

        :param login_lock:
        :param the_lock:
        :param security_lock:
        :param modification_lock:
        :param list_of_existing:
        :param list_of_existing_resources:
        """

        while True:
            try:
                self.update_credential_list()
                self.update_database()

                security_thread = self.create_security_threads(security_lock)
                connection_threads = self.create_connection_threads(the_lock)

                login_threads = self.create_credential_threads(login_lock, list_of_existing, list_of_existing_resources)
                response_threads = self.create_responders(the_lock)

                details_threads = self.create_detail_threads(the_lock)
                disconnect_threads = self.create_disconnect_threads(modification_lock)

                self.start_handling(security_thread, connection_threads, login_threads, response_threads,
                                    disconnect_threads, details_threads)

                if self.empty_server():
                    self.update_database()
                    self.__login_data_base.close_conn()
                    self.__main_data_base.close_conn()

                    self.disconnect_from_security()
                    self.__ips_data_base.close_conn()
                    break

            except AttributeError:
                print("wait huh")
                pass

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

    def create_connection_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, len(self.__all_details)):
            the_thread = threading.Thread(target=self.accept_clients, args=(lock, number))
            threads.append(the_thread)

        return threads

    def create_credential_threads(self, lock, list_of_existing, list_of_existing_resources):
        """

        :param lock:
        :param list_of_existing:
        :param list_of_existing_resources:
        :return:
        """

        threads = []

        for number in range(0, len(self.__all_details)):
            the_thread = threading.Thread(target=self.receive_credentials, args=(lock, number, list_of_existing,
                                                                                 list_of_existing_resources))
            threads.append(the_thread)

        return threads

    def create_responders(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, len(self.__all_details)):
            the_thread = threading.Thread(target=self.respond_to_client, args=(lock, number,))
            threads.append(the_thread)

        return threads

    def create_detail_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, len(self.__all_details)):
            the_thread = threading.Thread(target=self.send_updates, args=(lock, number,))
            threads.append(the_thread)

        return threads

    def create_disconnect_threads(self, lock):
        """

        :param lock:
        :return:
        """

        threads = []

        for number in range(0, len(self.__all_details)):
            the_thread = threading.Thread(target=self.eliminate_socket, args=(lock, number,))
            threads.append(the_thread)

        return threads

    def start_handling(self, security_thread, connection_threads, login_threads, response_threads, disconnect_threads,
                       detail_threads):
        """

        :param security_thread:
        :param connection_threads:
        :param response_threads:
        :param login_threads:
        :param disconnect_threads:
        :param detail_threads:
        """

        [thread.start() for thread in
         (connection_threads + login_threads + response_threads + detail_threads +
          disconnect_threads)]

        for thread in (connection_threads + login_threads + response_threads +
                       detail_threads + disconnect_threads):
            thread.join()

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

    def accept_clients(self, lock, number):
        """

        :param lock:
        :param number:
        :return:
        """

        with lock:
            try:
                if number < len(self.__all_details):
                    if self.__all_details[number].get("Client") is None:
                        if len(self.__sockets) < 3:
                            self.create_server_sockets()
                            return

                        else:
                            print("wait how?????", self.__all_details[number]["Client"])
                            for socket_c in self.__sockets:
                                try:
                                    socket_c.listen()
                                    socket_c.settimeout(0.1)

                                    connection, client_address = socket_c.accept()  # Accept clients request
                                    self.check_for_banned(connection, client_address, number)

                                    print(f"Client connected {connection.getpeername()}, {client_address[1]}")
                                    client_socket = connection

                                    self.__all_details[number]["Client"] = client_socket
                                    self.__all_details[number]["Sockets"] = socket_c

                                    self.__number_of_clients += 1
                                    self.__all_details[number]["Timer"] = (time.time(), 0)

                                    self.__all_details[number]["Timer"] = client_address[1]
                                    print("go back")
                                    return

                                except socket.timeout:
                                    break

            except TypeError:
                return

            except IndexError:
                return

            except Exception:
                return

    def receive_credentials(self, lock, number, list_of_existing, list_of_existing_resources):
        """

        :param list_of_existing_resources:
        :param list_of_existing:
        :param number:
        :param lock:
        :return:
        """

        with lock:
            try:
                print("e", self.__credentials[number])
                if (self.__all_details[number].get("Credentials") is None and
                        self.__all_details[number].get("Client") is not None):
                    print("d")
                    loging = Login(self.__all_details[number], list_of_existing, list_of_existing_resources,
                                   self.__credentials, number, self.__new_credentials, self.__number_of_clients,
                                   self.__list_of_banned_users)

                    (self.__all_details[number], self.__credentials, list_of_existing, list_of_existing_resources,
                     self.__new_credentials, self.__number_of_clients) = loging.run()

                    if self.__all_details[number].get("Credentials") is not None:
                        print("yayyyy")
                        self.__session_users[number] = self.__all_details[number].get("Credentials")[0]
                else:
                    print("l", self.__all_details)
            except Exception:
                return

    def respond_to_client(self, lock, index_of_client):
        """

        :param lock:
        :param index_of_client:
        :return:
        """

        with lock:
            try:
                if (self.__all_details[index_of_client].get("Credentials") is not None and
                        self.__all_details[index_of_client].get("Client") is not None):

                    client_socket = self.__all_details[index_of_client].get("Client")
                    timerr = 1/10000
                    data = self.deconstruct_data(client_socket, timerr)

                    if not data:
                        return

                    else:
                        print("tha dta", data)
                        if len(data) < 4:
                            return

                        if data == 1 or data[3] == 1:
                            self.__all_details[index_of_client]["Connected"] = 1
                            return

                        else:
                            the_data = data
                            if type(the_data) is tuple:
                                print('dup')
                                return

                            if the_data[0] == 'EXIT':
                                print("Client", index_of_client + 1, client_socket.getpeername(),
                                      "has left the server")
                                self.__all_details[index_of_client]["Connected"] = 1

                                self.__weapons[index_of_client] = the_data[2]
                                return

                            else:
                                print("data", the_data)

                                self.__locations[index_of_client] = the_data[0]

                                if the_data[1] is not None and len(the_data[1]) > 0:
                                    self.__chat[index_of_client] = the_data[1]
                          #      print(self.__chat, the_data[1])

                                self.__status[index_of_client] = the_data[2]
                                self.__status_frame_index[index_of_client] = the_data[4]

        #    except TypeError:
           #     print("Client", index_of_client + 1, "unexpectedly left")

           #     print("Waited", self.__all_details)
           #     return

          #  except ConnectionAbortedError:
          #      print("Client", index_of_client + 1, "unexpectedly left")
          #      print("Waited", self.__all_details)
          #      return

        #    except ConnectionResetError:
        #        print("Client", index_of_client + 1, "unexpectedly left")
        #        print("Waited", self.__all_details)
        #        return

        #    except IndexError:
        #        print("Client", index_of_client + 1, "unexpectedly left")
        #        print("Waited", self.__all_details)
        #        return

            except pickle.PickleError:
                print("what?")
                return

            except socket.timeout:
                return

            except KeyboardInterrupt:
                print("just stop")
                return

    def send_updates(self, lock, number):
        """

        :param lock:
        :param number:
        """

        with lock:
            try:
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
                        byte_data = self.create_message(list_data)

                        self.__all_details[number].get("Client").send(byte_data)

                    except ConnectionResetError:
                        pass

                    #self.__chat[number] = None

                else:
                    return

            except Exception:
                return

    def eliminate_socket(self, lock, number):
        """

        :param lock:
        :param number:
        """

        with lock:
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
            message = "EXIT".encode()

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
