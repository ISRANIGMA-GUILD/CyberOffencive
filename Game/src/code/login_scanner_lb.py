import socket
import pickle


class Login:

    def __init__(self, sock, list_of_existing, list_of_existing_resources,
                 credentials, new_credentials, banned_users, data, number=0):
        self.__list_of_existing = list_of_existing
        self.__sock = sock

        self.__list_of_existing_resources = list_of_existing_resources
        self.__credentials = credentials

        self.__number = number
        self.__new_credentials = new_credentials

        self.__list_of_banned_users = banned_users
        self.__data = data

    def run(self):

        self.handle_credentials()

        return (self.__data, self.__credentials, self.__list_of_existing, self.__list_of_existing_resources,
                self.__new_credentials)

    def handle_credentials(self):

        try:

            self.check_account()
            return

        except TypeError:
            print("Problematic")
            return

        except ConnectionResetError:
            print("Client", self.__number + 1, "unexpectedly left")
            print("Waited")
            return

        except AttributeError as e:
            print("start plssss", e)
            return

        except socket.timeout as e:
            print(e)
            return

        except KeyboardInterrupt:
            print("Server will end service")
            return

    def check_account(self):
        """

        """
        tuple_of_credentials = self.__data

        if self.__credentials.count(self.__data) <= 1:

            list_of_existing_users = [tup[0] for tup in self.__list_of_existing]
            list_of_existing_passes = [tup[1] for tup in self.__list_of_existing]

            the_big_ugly_list = [self.__list_of_banned_users[i][0]
                                 for i in range(0, len(self.__list_of_banned_users))]

            if tuple_of_credentials in self.__list_of_existing:

                if (self.__list_of_existing_resources[self.__number][0] != "banned"
                        and tuple_of_credentials[0] not in the_big_ugly_list):
                    print("Successful")
                    detail = self.__list_of_existing_resources[self.__list_of_existing.index(tuple_of_credentials)]

                    success = ["Success", detail]
                    success_pack = self.create_message(success)

                    self.successful_login(success_pack)
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

                    success_pack = self.create_message(["Success"])

                    self.successful_login(success_pack)
                    return True

        else:
            print("Wrong username or password")
            self.failed_login()

            return False

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

        m = self.__sock.send(success_pack)

        print("the", m)
        self.__credentials[self.__number] = self.__credentials[self.__number]

    def failed_login(self):
        """

        """

        success_pack = self.create_message(["Failure"])

        self.__sock.send(success_pack)
        self.__credentials[self.__number] = None

    def create_message(self, some_data):
        """
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """

        return pickle.dumps(some_data)
