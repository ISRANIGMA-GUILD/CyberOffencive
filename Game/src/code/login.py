import socket
import pickle


class Login:

    def __init__(self, details, list_of_existing, list_of_existing_resources,
                 credentials, number, new_credentials, banned_users, data,
                 zone, load_balance_socket, server_name):
        self.__details = details
        self.__list_of_existing = list_of_existing

        self.__list_of_existing_resources = list_of_existing_resources
        self.__credentials = credentials

        self.__number = number
        self.__new_credentials = new_credentials

        self.__list_of_banned_users = banned_users
        self.__sus = data

        self.__zone = zone
        self.__load_balance_socket = load_balance_socket

        self.__load_validation = {}
        self.__server_name = server_name

        self.__pre_success = False

    def run(self):

        self.handle_credentials()

        return (self.__details, self.__credentials, self.__list_of_existing, self.__list_of_existing_resources,
                self.__new_credentials)

    def handle_credentials(self):

        try:

            self.check_account()
            return

        except TypeError:
            print("Problematic")
            self.__details["Connected"] = 1
            return

        except ConnectionResetError as e:
            print(e)
            self.__details["Connected"] = 1
            return

        except AttributeError as e:
            print(e)
            return

        except socket.timeout:

            return

        except KeyboardInterrupt as e:
            print("Server will end service", e)
            self.__details["Connected"] = 1
            return

    def send_credential_to_load_balencer(self, credential):
        """
        check if the client exsist in anothe server and if he do he wont add and connect him
        Args:
            credential:
        """
        message = {'message_status': 'add', 'credential': credential, 'server_name': self.__server_name}
        self.__load_balance_socket.send(pickle.dumps(message))
        if self.receive_data_from_load_balancer():
            return True
        else:
            return False

    def receive_data_from_load_balancer(self):
        """

        """

        try:
            self.__load_balance_socket.settimeout(0.003)
            data = self.__load_balance_socket.recv(16000)

            if data:
                self.__load_validation = pickle.loads(data)

                if self.__load_validation['message_status'] == 'do_add':
                    return True

                elif self.__load_validation['message_status'] == 'dont':
                    return False

        except socket.timeout as e:
            print("timeout load balancer", e)
            pass

    def check_account(self):
        """

        """
        self.__details["Credentials"] = self.__sus
        if not self.__details["Credentials"]:
            pass

        else:

            tuple_of_credentials = self.__details["Credentials"]
            if self.send_credential_to_load_balencer(tuple_of_credentials):
                if "items" in list(self.__load_validation.keys()):
                    print("let him in")
            else:

                self.failed_login()
                self.__load_validation = {}
                return

            if self.__credentials.count(self.__details["Credentials"]) <= 1:

                list_of_existing_users = [tup[0] for tup in self.__list_of_existing]
                list_of_existing_passes = [tup[1] for tup in self.__list_of_existing]
                
                the_big_ugly_list = [self.__list_of_banned_users[i][0]
                                     for i in range(0, len(self.__list_of_banned_users))]

                if tuple_of_credentials in self.__list_of_existing:

                    if (self.__list_of_existing_resources[self.__number][0] != "BANNED"
                       and tuple_of_credentials[0] not in the_big_ugly_list):

                        if 'items' not in list(self.__load_validation.keys()):
                            detail = self.__list_of_existing_resources[self.__list_of_existing.index(tuple_of_credentials)]

                            success = ["Success", detail, self.__zone]
                            success_pack = self.create_message(success)

                            self.successful_login(success_pack)
                            self.__load_validation = {}
                        else:
                            success = ["Success", self.__load_validation.get("items"), self.__zone]
                            success_pack = self.create_message(success)

                            self.successful_login(success_pack)
                            self.__load_validation = {}
                        return True

                    else:
                        print("ENTRY DENIED")

                        self.failed_login()
                        return False

                else:

                    if (self.username_exists(list_of_existing_users, tuple_of_credentials) and
                       not self.password_exists(list_of_existing_passes, tuple_of_credentials) or
                       tuple_of_credentials in self.__credentials):

                        print("Wrong username or password")

                        self.failed_login()
                        return False

                    else:

                        self.__new_credentials.append(tuple_of_credentials)
                        self.__list_of_existing.append(tuple_of_credentials)
                        print("NEW ACCOUNT YAY :)")

                        success_pack = self.create_message(["Success", self.__zone])

                        self.successful_login(success_pack)
                        return True

    def username_exists(self, list_of_existing_users, tuple_of_credentials):
        """

        :param list_of_existing_users:
        :param tuple_of_credentials:
        :return:
        """

        return tuple_of_credentials[0] in list_of_existing_users

    def password_exists(self, list_of_existing, tuple_of_credentials):
        """

        :param list_of_existing:
        :param tuple_of_credentials:
        :return:
        """

        return tuple_of_credentials[1] in list_of_existing

    def successful_login(self, success_pack):
        """

        :param success_pack:
        """

        m = self.__details["Client"].send(success_pack)
        self.__credentials[self.__number] = self.__details["Credentials"]

    def failed_login(self):
        """

        """

        success_pack = self.create_message(["Failure"])

        self.__details["Client"].send(success_pack)
        self.__details["Credentials"] = None

    def create_message(self, some_data):
        """
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """

        return pickle.dumps(some_data)
