import socket
import time
import pickle


class Login:

    def __init__(self, details, list_of_existing, list_of_existing_resources,
                 credentials, number, new_credentials, number_of_clients, banned_users, data,
                 zone):
        self.__details = details
        self.__list_of_existing = list_of_existing

        self.__list_of_existing_resources = list_of_existing_resources
        self.__credentials = credentials

        self.__number = number
        self.__new_credentials = new_credentials

        self.__number_of_clients = number_of_clients
        self.__list_of_banned_users = banned_users

        self.__sus = data
        self.__zone = zone

    def run(self):

        self.handle_credentials()

        return (self.__details, self.__credentials, self.__list_of_existing, self.__list_of_existing_resources,
                self.__new_credentials, self.__number_of_clients)

    def handle_credentials(self):

        try:

            self.check_account()
            return

        except TypeError:
            print("Problematic")
            self.__details["Connected"] = 1
            return

        except ConnectionResetError:
            print("Client", self.__number + 1, self.__details["Client"].getpeername(),
                  "unexpectedly left")
            self.__details["Connected"] = 1

            print("Waited")
            return

        except AttributeError:
            print("start plssss")
            return

        except socket.timeout:
            print(self.__details["Timer"])
            elapsed = time.time() - self.__details["Timer"]

            hour, minutes, seconds = time.strftime("%Hh %Mm %Ss",
                                                   time.gmtime(elapsed)).split(' ')
            self.__details["Timer"] = (self.__details["Timer"], minutes)

            if '01' in minutes:
                self.__details["Connected"] = 1

            return

        except KeyboardInterrupt:
            print("Server will end service")
            self.__details["Connected"] = 1
            return

    def check_account(self):
        """

        """
        self.__details["Credentials"] = self.__sus
        if not self.__details["Credentials"]:
            pass

        else:

            tuple_of_credentials = self.__details["Credentials"]

            if self.__credentials.count(self.__details["Credentials"]) <= 1:

                list_of_existing_users = [tup[0] for tup in self.__list_of_existing]
                list_of_existing_passes = [tup[1] for tup in self.__list_of_existing]
                
                the_big_ugly_list = [self.__list_of_banned_users[i][0]
                                     for i in range(0, len(self.__list_of_banned_users))]

                if tuple_of_credentials in self.__list_of_existing and self:

                    if (self.__list_of_existing_resources[self.__number][0] != "banned"
                       and tuple_of_credentials[0] not in the_big_ugly_list):
                        print("Successful")
                        detail = self.__list_of_existing_resources[self.__list_of_existing.index(tuple_of_credentials)]

                        success = ["Success", detail, self.__zone]

                        success_pack = self.create_message(success)
                        m = self.__details["Client"].send(success_pack)
                        print("the", m)
                        self.__credentials[self.__number] = self.__details["Credentials"]
                        return True

                    else:
                        print("ENTRY DENIED")

                        success_pack = self.create_message(["Failure"])
                        m = self.__details["Client"].send(success_pack)
                        print("the", m)
                        self.__details["Credentials"] = None
                        return False

                else:

                    if (self.username_exists(list_of_existing_users, tuple_of_credentials) and
                       not self.password_exists(list_of_existing_passes, tuple_of_credentials) or
                       tuple_of_credentials in self.__credentials):

                        print("Wrong username or password")

                        success_pack = self.create_message(["Failure"])
                        self.__details["Client"].send(success_pack)

                        self.__details["Credentials"] = None
                        return False

                    else:

                        self.__new_credentials.append(tuple_of_credentials)
                        self.__list_of_existing.append(tuple_of_credentials)
                        print("NEW ACCOUNT YAY :)")

                        success_pack = self.create_message(["Success", self.__zone])

                        self.__details["Client"].send(success_pack)
                        self.__credentials[self.__number] = self.__details["Credentials"]
                        return True

            else:
                print("Wrong username or password")

                success_pack = self.create_message(["Failure"])

                self.__details["Client"].send(success_pack)
                self.__details["Credentials"] = None
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

    def create_message(self, some_data):
        """
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """

        return pickle.dumps(some_data)
