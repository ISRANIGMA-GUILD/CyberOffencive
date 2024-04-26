from scapy.layers.tls.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import socket
import pickle

MAX_MSG_LENGTH = 1024


class Login:

    def __init__(self, details, list_of_existing, list_of_existing_resources,
                 credentials, number, new_credentials, number_of_clients, banned_users):
        self.__details = details
        self.__list_of_existing = list_of_existing

        self.__list_of_existing_resources = list_of_existing_resources
        self.__credentials = credentials

        self.__number = number
        self.__new_credentials = new_credentials

        self.__number_of_clients = number_of_clients
        self.__list_of_banned_users = banned_users

    def run(self):
        print("b")
        start = time.time()
        self.handle_credentials()

        if self.__details["Credentials"] is None:
            elapsed = time.time() - self.__details["Timer"][0]

            hour, minutes, seconds = time.strftime("%Hh %Mm %Ss",
                                                   time.gmtime(elapsed)).split(' ')
            self.__details["Timer"] = (self.__details["Timer"][0], minutes)

            if '01' in minutes:
                self.__details["Connected"] = 1
        end = time.time()

        print(time.strftime("%Hh %Mm %Ss", time.gmtime(end - start)).split(' '))
        return (self.__details, self.__credentials, self.__list_of_existing, self.__list_of_existing_resources,
                self.__new_credentials, self.__number_of_clients)

    def handle_credentials(self):

        try:
            self.__details["Client"].settimeout(0.1)
            data = self.deconstruct_data()
            if not data:
                return

            else:
                data_iv, data_c_t, data_tag = data[0], data[1], data[2]

                if self.invalid_data(data_iv, data_c_t, data_tag):
                    return

                else:
                    data = self.decrypt_data(data_iv, data_c_t, data_tag)

                    if data == b'EXIT':
                        self.__details["Connected"] = 1
                        return
                    else:
                        self.__details["Credentials"] = pickle.loads(data)
                        self.check_account()
                        self.__credentials[str(self.__number)] = self.__details["Credentials"]
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
            return

        except socket.timeout:
            elapsed = time.time() - self.__details["Timer"][0]

            hour, minutes, seconds = time.strftime("%Hh %Mm %Ss",
                                                   time.gmtime(elapsed)).split(' ')
            self.__details["Timer"] = (self.__details["Timer"][0], minutes)

            if '01' in minutes:
                self.__details["Connected"] = 1

            return

        except KeyboardInterrupt:
            print("Server will end service")
            self.__details["Connected"] = 1
            return

    def deconstruct_data(self):

        data_pack = self.__details["Client"].recv(MAX_MSG_LENGTH)

        try:
            if not data_pack:
                return

            elif TLSAlert in TLS(data_pack):
                print("THAT IS A SNEAKY CLIENT")
                return 0, 1, 2

            else:
                data_pack = TLS(data_pack)

                data = data_pack[TLS][TLSApplicationData].data
                data_iv = data[:12]

                data_tag = data[len(data) - 16:len(data)]
                data_c_t = data[12:len(data) - 16]

        except struct.error:
            print("dont")
            return

        except socket.timeout:
            print("out of time")
            return

        except IndexError:
            return

        return data_iv, data_c_t, data_tag

    def invalid_data(self, data_iv, data_c_t, data_tag):
        """

        :param data_iv:
        :param data_c_t:
        :param data_tag:
        :return:
        """

        return data_iv == 0 and data_c_t == 1 and data_tag == 2

    def check_account(self):
        """

        """

        if not self.__details["Credentials"]:
            pass

        else:

            tuple_of_credentials = self.__details["Credentials"]

            count = 0

            for i in range(0, len(self.__credentials)):
                if self.__details["Credentials"] == self.__credentials[str(i)]:
                    count += 1

            if count <= 1:

                list_of_existing_users = [tup[0] for tup in self.__list_of_existing]
                the_big_ugly_list = [self.__list_of_banned_users[i][0]
                                     for i in range(0, len(self.__list_of_banned_users))]

                if tuple_of_credentials in self.__list_of_existing:

                    if (self.__list_of_existing_resources[self.__number][0] != "banned"
                       and tuple_of_credentials[0] not in the_big_ugly_list):
                        print("Successful")
                        detail = self.__list_of_existing_resources[self.__list_of_existing.index(tuple_of_credentials)]

                        success = pickle.dumps(["Success", detail])
                        success_msg = self.encrypt_data(self.__details["Keys"][0], success,
                                                        self.__details["Keys"][1])

                        success_pack = self.create_message(success_msg)
                        self.__details["Client"].send(bytes(success_pack[TLS]))
                        return True

                    else:
                        print("ENTRY DENIED")
                        success = pickle.dumps(["Failure"])

                        success_msg = self.encrypt_data(self.__details["Keys"][0], success, self.__details["Keys"][1])
                        success_pack = self.create_message(success_msg)

                        self.__details["Client"].send(bytes(success_pack[TLS]))
                        self.__details["Credentials"] = None
                        return False

                else:

                    if (self.username_exists(list_of_existing_users, tuple_of_credentials) and
                       not self.password_exists(self.__list_of_existing, tuple_of_credentials)):

                        print("Wrong username or password")
                        success = pickle.dumps(["Failure"])

                        success_msg = self.encrypt_data(self.__details["Keys"][0], success, self.__details["Keys"][1])
                        success_pack = self.create_message(success_msg)

                        self.__details["Client"].send(bytes(success_pack[TLS]))
                        self.__details["Credentials"] = None
                        return False

                    else:

                        self.__new_credentials.append(tuple_of_credentials)
                        print("NEW ACCOUNT YAY :)")

                        success = pickle.dumps(["Success"])
                        success_msg = self.encrypt_data(self.__details["Keys"][0], success, self.__details["Keys"][1])

                        success_pack = self.create_message(success_msg)
                        self.__details["Client"].send(bytes(success_pack[TLS]))
                        return True

            else:
                print("Wrong username or password")
                success = pickle.dumps(["Failure"])

                success_msg = self.encrypt_data(self.__details["Keys"][0], success, self.__details["Keys"][1])
                success_pack = self.create_message(success_msg)

                self.__details["Client"].send(bytes(success_pack[TLS]))
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

        full_data = some_data[0] + some_data[1] + some_data[2]
        data_packet = TLS(msg=TLSApplicationData(data=full_data))
        data_message = self.prepare_packet_structure(data_packet)

        return data_message

    def prepare_packet_structure(self, the_packet):
        """

        :param the_packet:
        :return:
        """

        return the_packet.__class__(bytes(the_packet))

    def encrypt_data(self, key, plaintext, associated_data):
        """
         Encrypt data before sending it to the client
        :param key: The server encryption key
        :param plaintext: The data which will be encrypted
        :param associated_data: Data which is associated with yet not encrypted
        :return: The iv, the encrypted data and the encryption tag
        """

        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()

        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv, ciphertext, encryptor.tag

    def decrypt_data(self, iv, ciphertext, tag):
        """
         Decrypt the data received by the client
        :param iv: The iv
        :param ciphertext: The encrypted data
        :param tag: The encryption tag
        :return: The decrypted data
        """

        decryptor = Cipher(algorithms.AES(self.__details["Keys"][0]), modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(self.__details["Keys"][1])

        return decryptor.update(ciphertext) + decryptor.finalize()

