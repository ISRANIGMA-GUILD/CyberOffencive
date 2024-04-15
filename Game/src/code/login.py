from scapy.layers.tls.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import socket
import pickle

MAX_MSG_LENGTH = 1024


class Login:

    def __init__(self, client_socket, encryption_key, auth, list_of_existing, list_of_existing_resources, time_log,
                 credentials, number, new_credentials, server_socket):
        self.__client_socket = client_socket
        self.__encryption_key = encryption_key
        self.__auth = auth
        self.__list_of_existing = list_of_existing
        self.__list_of_existing_resources = list_of_existing_resources
        self.__credentials = credentials
        self.__number = number
        self.__time = time_log
        self.__new_credentials = new_credentials
        self.__server_socket = server_socket

    def run(self):
        self.handle_credentials()

        return (self.__client_socket, self.__credentials, self.__list_of_existing, self.__list_of_existing_resources,
                self.__time, self.__new_credentials, self.__server_socket)

    def handle_credentials(self):

        try:
            self.__client_socket.settimeout(0.1)
            data = self.deconstruct_data()
            if not data:
                return

            else:
                data_iv, data_c_t, data_tag = data[0], data[1], data[2]

                if self.invalid_data(data_iv, data_c_t, data_tag):
                    return

                else:
                    self.__credentials[str(self.__number)] = pickle.loads(self.decrypt_data(data_iv, data_c_t, data_tag))
                    self.check_account()
                    return

        except TypeError:
            print("Problematic")
            self.eliminate_socket(self.__number)
            return

        except ConnectionResetError:
            print("Client", self.__number + 1, self.__client_socket.getpeername(),
                  "unexpectedly left")
            self.eliminate_socket(self.__number)

            print("Waited")
            return

        except AttributeError:
            return

        except socket.timeout:
            elapsed = time.time() - self.__time[0]

            hour, minutes, seconds = time.strftime("%Hh %Mm %Ss",
                                                   time.gmtime(elapsed)).split(' ')
            self.__time = (self.__time[0], minutes)

            if '01' in minutes:
                self.eliminate_socket(self.__number)

            return

        except KeyboardInterrupt:
            print("Server will end service")
            return

    def deconstruct_data(self):

        data_pack = self.__client_socket.recv(MAX_MSG_LENGTH)

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

        if not self.__credentials[str(self.__number)]:
            pass

        else:

            tuple_of_credentials = self.__credentials[str(self.__number)]

            count = 0

            for i in range(0, len(self.__credentials)):
                if self.__credentials[str(self.__number)] == self.__credentials[str(i)]:
                    count += 1

            if count <= 1:

                list_of_existing_users = [tup[0] for tup in self.__list_of_existing]

                if tuple_of_credentials in self.__list_of_existing:

                    if self.__list_of_existing_resources[self.__number][1] != "Banned":
                        print("Successful")
                        success = f"Success {self.__list_of_existing_resources[self.__number]}".encode()
                        success_msg = self.encrypt_data(self.__encryption_key, success,
                                                        self.__auth)

                        success_pack = self.create_message(success_msg)
                        self.__client_socket.send(bytes(success_pack[TLS]))
                        return True

                    else:
                        print("ENTRY DENIED")
                        success = "Failure".encode()

                        success_msg = self.encrypt_data(self.__encryption_key, success, self.__auth)
                        success_pack = self.create_message(success_msg)

                        self.__client_socket.send(bytes(success_pack[TLS]))
                        self.__credentials[str(self.__number)] = None
                        return False

                else:

                    if (self.username_exists(list_of_existing_users, tuple_of_credentials) and
                       not self.password_exists(self.__list_of_existing, tuple_of_credentials)):

                        print("Wrong username or password")
                        success = "Failure".encode()

                        success_msg = self.encrypt_data(self.__encryption_key, success, self.__auth)
                        success_pack = self.create_message(success_msg)

                        self.__client_socket.send(bytes(success_pack[TLS]))
                        self.__credentials[str(self.__number)] = None
                        return False

                    else:

                        self.__new_credentials.append(tuple_of_credentials)
                        print("NEW ACCOUNT YAY :)")

                        success = "Success".encode()
                        success_msg = self.encrypt_data(self.__encryption_key, success, self.__auth)

                        success_pack = self.create_message(success_msg)
                        self.__client_socket.send(bytes(success_pack[TLS]))
                        return True

            else:
                print("Wrong username or password")
                success = "Failure".encode()

                success_msg = self.encrypt_data(self.__encryption_key, success, self.__auth)
                success_pack = self.create_message(success_msg)

                self.__client_socket.send(bytes(success_pack[TLS]))
                self.__credentials[str(self.__number)] = None
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

        decryptor = Cipher(algorithms.AES(self.__encryption_key), modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(self.__auth)

        return decryptor.update(ciphertext) + decryptor.finalize()

    def eliminate_socket(self, number):
        """

        :param number:
        """

        self.__client_socket.close()
        self.__server_socket.close()

        self.__server_socket = None
        self.__client_socket = None
        self.__credentials[str(number)] = None

