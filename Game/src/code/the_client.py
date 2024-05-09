import pickle
import ssl
from wrapper_of_the_client_socks import *
from creepy import *
from dnssec_client import *
from scapy.all import *
import socket
import pygame
from socks import *

pygame.init()
SYN = 2
ACK = 16
MY_IP = conf.route.route('0.0.0.0')[1]
MAX_MSG_LENGTH = 1024
THE_BIG_LIST = {"0": "'", "1": ";", "2": "=", "3": '"', "4": "*", "5": "AND", "6": "SELECT", "7": "/", "8": "#",
                "9": "SQL", "10": "FROM", "11": "(", "12": ")", "13": "+", "14": "UNION", "15": "ALL", "16": ">",
                "17": "<", "18": "–dbs", "19": "-D", "20": "-T", "21": "-", "22": ".php", "23": "SLEEP", "24": "@",
                "25": "CREATE USER", "26": "`", "27": "select", "28": "from", "29": "union", "30": "union",
                "31": "create user", "32": "sleep", "33": "all", "34": "and", "35": "INSERT", "36": "UPDATE",
                "37": "DELETE", "38": "\\"}
FONT = pygame.font.Font(None, 42)
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
GRAY = (200, 200, 200)
IMAGE = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\Graphics\\LoginScreen\\login.png'


class Client:

    def __init__(self):
        self.__the_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__timer = 0

        self.__start_time = 0
        self.player = CreePy()

        self.__logged = ""

    # self.v = self.player.get_volume()

    def run(self):
        """

        """

        #  self.player.run()

        server_ip, server_port = self.format_socket()
        self.connect_to_socket(server_ip, server_port)

        self.__start_time = time.time()

        while True:
            try:
                details = self.details_entry()
                if details == 1:
                    print("leaving1")
                    message = 'EXIT'.encode()

                    self.__the_client_socket.send(message)
                    print("leaving3")
                    return 1

                else:
                    print("this", details)
                    checker = self.check_success(details)
                    print("the checker", checker[0])
                    self.__logged = checker
                    if self.__logged[0] == 'Success':
                        print("Nice")
                        return checker

                    elif self.__logged[0] == "Failure":
                        print("retry")
                        details = self.details_entry()

                    else:
                        print("retry")
                        continue

            except ConnectionAbortedError:
                print("Leaving the game1")

                return 1

            except ssl.SSLEOFError:
                print("stop")
                time.sleep(0.02)

            except ConnectionResetError:
                print("Leaving the game1")

                return 1

            except TypeError:
                print("Leaving the game1")
                message = 'EXIT'.encode()

                self.__the_client_socket.send(message)
                return 1

            except KeyboardInterrupt:
                print("Leaving the game")

                return 1

    def connect_to_socket(self, server_ip, server_port):
        """

        :param server_ip:
        :param server_port:
        :return:
        """

        count = 0
        while True:
            print(f'ip:port = {server_ip}:{server_port}')
            time.sleep(1)
            try:
                print("Trying to connect...")
                self.__the_client_socket = TLSSocketWrapper(server_ip).create_sock()
                self.__the_client_socket.connect((server_ip, server_port))
                print("Connection established.")
                break
            
            except ConnectionRefusedError:
                print("Connection refused. Retrying...")
                server_port = self.choose_port()
        
            except TimeoutError:
                print("Connection timeout. Retrying...")
                server_port = self.choose_port()
        
            except ValueError as ve:
                # Print the specific ValueError message for debugging
                print(f"ValueError: {ve}")
                print("Retrying...")
                server_port = self.choose_port()
        
            except Exception as e:
                # Catch any other exceptions for debugging
                print(f"Unexpected error: {e}")
                print("Retrying...")
                server_port = self.choose_port()

        print("Success")
        count = 0

    def format_socket(self):
        """

        :return:
        """

        server_port = self.choose_port()
        server_ip = self.find_ip()

        return server_ip, server_port

    def choose_port(self):
        """

        :return:
        """
        list_port = [6921, 8843, 8820]
        server_port = random.choice(list_port)
        print(server_port)

        return server_port

    def find_ip(self):
        """

        :return:
        """

        while True:
            #   self.good_music()
            servers = Discoverer()
            server_ip = servers.discover_server()
            print(server_ip)

            if self.ip_v_four_format(server_ip) and not self.empty_string(server_ip):
                return server_ip

    def empty_string(self, message):
        """

        :param message:
        :return:
        """

        return message is None or ' ' in message or message == ''

    def ip_v_four_format(self, ip_address):
        """

        :param ip_address:
        :return:
        """

        return (ip_address.count('.') == 3 and ''.join(ip_address.split('.')).isnumeric() and
                len(''.join(ip_address.split('.'))) <= 12)

    def receive_data(self, timer):
        """
         Dissect the data received from the server
        :return: The data iv, data and tag
        """

        try:
            self.__the_client_socket.settimeout(timer)
            data_pack = self.__the_client_socket.recv(73)

            if not data_pack:
                return

            else:
                data = pickle.loads(data_pack)

            return data

        except IndexError:
            return

        except socket.timeout:
            return

        except struct.error:
            return

    def create_message(self, some_data):
        """
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """

        return pickle.dumps(some_data)

    def details_entry(self):
        """

         Turn the data into a proper message
        :return: The full data message
        """
        print("one time only ok......")
        while True:
            #  self.good_music()
            try:
                user, password = self.login()
                print("Credes", user, password)
                if user == 1 and password == 1:
                    return 1

                if self.empty_string(user) or self.empty_string(password):
                    print("Please enter the requested information")

                elif user == 'EXIT' or password == 'EXIT':
                    print("YOU CAN'T EXIT AT LOGIN!")

                elif self.malicious_message(user) or self.malicious_message(password):
                    print("Don't mess with Shmulik")

                else:
                    user = user
                    password = password

                    print(user, password)
                    credentials = (user, password)

                    pack = self.create_message(credentials)
                    return pack

            except KeyboardInterrupt:
                message = 'EXIT'.encode()
                print(message)

                data = [message]
                full_msg = self.create_message(data)

                self.__the_client_socket.send(full_msg)
                self.__the_client_socket.close()

                return

    def login(self):
        """

        """

        username = ""
        password = ""

        screen_width = 1200
        screen_height = 730

        screen = pygame.display.set_mode((screen_width, screen_height))
        pygame.display.set_caption("Login Screen")

        font = pygame.font.SysFont('arial', 32)
        entering_username = True

        while True:
            # self.good_music()
            img = pygame.image.load(IMAGE)
            screen.blit(img, (0, 0))
            pygame.display.flip()

            self.__timer = time.time() - self.__start_time
            hour, minutes, seconds = time.strftime("%Hh %Mm %Ss",
                                                   time.gmtime(self.__timer)).split(' ')
            if '01' in minutes:
                self.__the_client_socket.close()
                return 1, 1

            if entering_username:
                if len(username) < 13:
                    self.draw_text(username, font, BLACK, screen, 246, 420)
                else:
                    self.draw_text(username[3:], font, BLACK, screen, 246, 420)
            else:
                if len(password) < 13:
                    self.draw_text('*' * len(password), font, BLACK, screen, 246, 522)
                else:
                    self.draw_text('*' * len(password[3:]), font, BLACK, screen, 246, 522)

            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    pygame.quit()
                    sys.exit()

                elif event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_BACKSPACE:
                        if entering_username:
                            if username:
                                username = username[:-1]
                        else:
                            if password:
                                password = password[:-1]
                    elif event.key == pygame.K_RETURN:
                        if entering_username:
                            entering_username = False
                        else:
                            if username is not None and password is not None:
                                print("Login successful!")
                                return username, password
                            else:
                                print("Login failed!")
                    else:
                        if entering_username:
                            if len(username) < 20:
                                username += event.unicode
                        else:
                            if len(password) < 20:
                                password += event.unicode

            pygame.display.update()

    def draw_text(self, text, font, color, surface, x, y):
        """

        :param text:
        :param font:
        :param color:
        :param surface:
        :param x:
        :param y:
        """

        text_tobj = font.render(text, 1, color)
        text_rect = text_tobj.get_rect()

        text_rect.topleft = (x, y)
        surface.blit(text_tobj, text_rect)

    def check_success(self, details):
        """

        :param details:
        :return:
        """

        #   self.good_music()
        print("details", details)
        while True:
            try:
                print(details, "\n the check", self.__logged)
          #      if len(self.__logged) == 0:
                print("please")
                self.__the_client_socket.send(details)
                print("details1", details)
                timer = 1
                success = self.receive_data(timer)
             #   time.sleep(5)
                print("Did succeed?", success)

                if success is None:
                    print("Fail")
                    pass

                else:
                    decrypt = success
                    print(decrypt)

                    if "Success" == decrypt[0]:
                        print("success")
                        return decrypt

                    elif "Failure" == decrypt[0]:
                        print("wrong password or username")
                        return decrypt

            except socket.timeout:
                pass

    def malicious_message(self, message):
        """

        :param message:
        :return:
        """

        #  self.good_music()
        for index in range(0, len(THE_BIG_LIST)):
            #   self.good_music()
            if message is not None:
                if THE_BIG_LIST.get(str(index)) in message:
                    return True

        if message is not None:
            if message.isnumeric() and sys.maxsize <= int(message):
                return True

        return False

    def update_server(self, public_data, private_data):
        """

        :param public_data:
        :param private_data:
        :return:
        """

        # self.good_music()

        try:
            if public_data[0] == "EXIT":
                print("leaving")
                data = ["EXIT", 1, private_data]

                full_msg = self.create_message(data)

                self.__the_client_socket.send(full_msg)

            else:

                full_msg = self.create_message(public_data)
                print("the full message", full_msg)
                self.__the_client_socket.send(full_msg)

            # if message == 'EXIT':
            # self.__the_client_socket.close()
            # return

        except TypeError:
            return

        except ConnectionResetError:
            print("no no no n")
            message = ["EXIT", 1, private_data]

            full_msg = self.create_message(message)

            self.__the_client_socket.send(full_msg)
            self.__the_client_socket.close()

            return

        except ConnectionRefusedError:
            print("Retrying")

        except ConnectionAbortedError:
            print("srsly")
            message = ["EXIT", 1, private_data]
            full_msg = self.create_message(message)

            self.__the_client_socket.send(full_msg)
            self.__the_client_socket.close()

            return

        except pickle.PickleError:
            return

        except socket.timeout:
            return

        except KeyboardInterrupt:
            print("Server is shutting down")
            message = ["EXIT", 1, private_data]

            full_msg = self.create_message(message)
            self.__the_client_socket.send(full_msg)

            self.__the_client_socket.close()
            return

    def receive_location(self):
        """

        :return:
        """

        try:
            timer = 0.01
            data_recv = self.receive_data(timer)

            if not data_recv:
                pass

            else:
                print("successsss")
                return data_recv

        except socket.timeout:
            print("epic fail")
            return

    def good_music(self):
        """

        """

        self.v.SetMute(1, None)
        self.v.SetMasterVolumeLevelScalar(1.0, None)


def main():
    """
    Main function
    """
    client = Client()
    client.run()


if __name__ == '__main__':
    main()
