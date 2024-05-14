import pickle
from creepy import *
from dnssec_client import *
import pygame
import sys
from socks import *
from settings import *
from clientpasswordgen import *
from serverpassword import *

MY_IP = socket.gethostbyname(socket.gethostname())
MAX_MSG_LENGTH = 1024
THE_BIG_LIST = {"0": "'", "1": ";", "2": "=", "3": '"', "4": "*", "5": "AND", "6": "SELECT", "7": "/", "8": "#",
                "9": "SQL", "10": "FROM", "11": "(", "12": ")", "13": "+", "14": "UNION", "15": "ALL", "16": ">",
                "17": "<", "18": "–dbs", "19": "-D", "20": "-T", "21": "-", "22": ".php", "23": "SLEEP", "24": "@",
                "25": "CREATE USER", "26": "`", "27": "select", "28": "from", "29": "union", "30": "union",
                "31": "create user", "32": "sleep", "33": "all", "34": "and", "35": "INSERT", "36": "UPDATE",
                "37": "DELETE", "38": "\\"}
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
GRAY = (200, 200, 200)
IMAGE = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\Graphics\\LoginScreen\\login.png'


class Client:

    def __init__(self):
        pygame.init()
        pygame.mixer.init()

        pygame.font.init()
        self.font = pygame.font.Font(FONT_PATH, 60)
        self.__the_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__timer = 0

        self.__start_time = 0
        self.player = CreePy()

        self.__logged = ""
        self.__login_thingy = pygame.Rect(0, 0, 600, 1100)
        self.__user_box = pygame.Rect(10, 300, 100, 75)
        self.__pass_box = pygame.Rect(10, 500, 100, 75)

        self.__o_width = max(450, 50 + 10)
        self.__i_width = max(450, 50 + 10)
        self.__m_width = max(500, 50 + 10)

        self.__user_box.w = self.__o_width
        self.__pass_box.w = self.__i_width
        self.__login_thingy.w = self.__m_width

        # self.v = self.player.get_volume()

    def run(self):
        """

        """

        #  self.player.run()

        server_ip, server_port = self.format_socket()
        screen = pygame.display.set_mode((1920, 1080))

        clock = pygame.time.Clock()
        m = self.connect_to_socket(server_ip, server_port, screen, clock)

        if m == 1:
            return 1

        self.__start_time = time.time()

        while True:
            try:
                img = pygame.image.load(IMAGE)
                screen.blit(img, (0, 0))

                pygame.draw.rect(screen, (0, 0, 255), self.__login_thingy)
                pygame.draw.rect(screen, (255, 255, 255), self.__user_box)
                pygame.draw.rect(screen, (255, 255, 255), self.__pass_box)

                start_button = self.font.render('USERNAME', True, (255, 215, 0))
                screen.blit(start_button, (10, 210))

                start_button = self.font.render('PASSWORD', True, (255, 215, 0))
                screen.blit(start_button, (10, 430))
                pygame.display.update()

                details = self.details_entry(screen, clock)

                if details == 1:
                  #  print("leaving1")
                    message = pickle.dumps(["EXIT"])

                    self.__the_client_socket.send(message)
               #     print("leaving3")

                    pygame.display.update()
                    clock.tick(FPS)
                    return 1

                else:
                    print("this", details)
                    checker = self.check_success(details)

                    print("the checker", checker)
                    self.__logged = checker

                    if self.__logged[0] == 'Success':
                        print("Nice")
                        pygame.display.update()

                        clock.tick(FPS)
                        return checker

                    elif self.__logged[0] == "Failure":
                        print("retry")
                        details = self.details_entry(screen, clock)

                    else:
                        print("retry")

                        continue
                pygame.display.update()
                clock.tick(FPS)
            except ConnectionAbortedError:
                print("Leaving the game1")
                pygame.display.update()
                clock.tick(FPS)
                return 1

            except ssl.SSLEOFError:
                print("stop")
                time.sleep(0.02)
                pygame.display.update()
                clock.tick(FPS)

            except ConnectionResetError:
                print("Leaving the game1")
                pygame.display.update()
                clock.tick(FPS)
                return 1

            except TypeError:
                print("Leaving the game1")
                message = pickle.dumps(["EXIT"])

                self.__the_client_socket.send(message)
                pygame.display.update()
                clock.tick(FPS)
                return 1

            except KeyboardInterrupt:
                print("Leaving the game")
                pygame.display.update()
                clock.tick(FPS)
                return 1

            pygame.display.update()
            clock.tick(FPS)

    def connect_to_socket(self, server_ip, server_port, screen, clock):
        """

        :param screen:
        :param clock:
        :param server_ip:
        :param server_port:
        :return:
        """

        while True:
            img = pygame.image.load(IMAGE)
            screen.blit(img, (0, 0))

            pygame.display.update()
            print(f'ip:port = {server_ip}:{server_port}')

            try:
                print("Trying to connect...")
                self.__the_client_socket = TLSSocketWrapper(server_ip).create_sock()

                self.__the_client_socket.connect((server_ip, server_port))
                self.__the_client_socket.send(pickle.dumps([GetPassword(128).run()]))

                the_real_pass = Verifier(256).run()
                their_pass = pickle.loads(self.__the_client_socket.recv(MAX_MSG_LENGTH))

                if their_pass[0] != the_real_pass:
                    print("its a fake quit!!!!!!!!!!")
                    pygame.display.update()

                    clock.tick(FPS)
                    self.__the_client_socket.close()

                    return 1

                print("Connection established.")

                pygame.display.update()
                clock.tick(FPS)
                break
            
            except ConnectionRefusedError:
                print("Connection refused. Retrying...")
                server_port = self.choose_port()

            except ConnectionResetError:
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

            except pickle.UnpicklingError as ve:
                print(f"FAKE SERVER DONT CONNECT: {ve}")
                print("Retrying...")

                server_port = self.choose_port()

            except Exception as e:
                # Catch any other exceptions for debugging
                print(f"Unexpected error: {e}")
                print("Retrying...")

                server_port = self.choose_port()

            pygame.display.update()
            clock.tick(FPS)

        pygame.display.update()
        clock.tick(FPS)
        print("Success")

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
            server_discover = ServerDiscoveryClient()
            servers_ip = server_discover.discover_server()

            print(servers_ip)
            if servers_ip is None:
                pass

            else:
                if self.ip_v_four_format(servers_ip) and not self.empty_string(servers_ip):
                    return servers_ip

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
            data_pack = self.__the_client_socket.recv(1024)
        #    print("data pack", data_pack)

            if not data_pack:
                return

            else:
                data = pickle.loads(data_pack)

            return data

        except IndexError:
            return

        except socket.timeout:
            return

    def create_message(self, some_data):
        """
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """

        return pickle.dumps(some_data)

    def details_entry(self, screen, clock):
        """

         Turn the data into a proper message
        :return: The full data message
        """
        print("one time only ok......")
        while True:
            #  self.good_music()
            try:
                img = pygame.image.load(IMAGE)
                screen.blit(img, (0, 0))

                user, password = self.login(screen)
                print("Credes", user, password)

                if user == 1 and password == 1:

                    pygame.display.update()
                    clock.tick(FPS)
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

                    pygame.display.update()
                    clock.tick(FPS)
                    return pack

            except KeyboardInterrupt:
                message = pickle.dumps(["EXIT"])
                print(message)

                data = [message]
                full_msg = self.create_message(data)

                self.__the_client_socket.send(full_msg)
                self.__the_client_socket.close()

                pygame.display.update()
                clock.tick(FPS)
                return

            pygame.display.update()
            clock.tick(FPS)

    def login(self, screen):
        """

        """

        username = ""
        password = ""

        pygame.display.set_caption("Login Screen")
        entering_username = True

        while True:
            # self.good_music()
            img = pygame.image.load(IMAGE)
            screen.blit(img, (0, 0))

            pygame.draw.rect(screen, (0, 0, 255), self.__login_thingy)
            pygame.draw.rect(screen, (255, 255, 255), self.__user_box)
            pygame.draw.rect(screen, (255, 255, 255), self.__pass_box)

            start_button = self.font.render('USERNAME', True, (255, 215, 0))
            screen.blit(start_button, (10, 210))
            pygame.display.update()

            start_button = self.font.render('PASSWORD', True, (255, 215, 0))
            screen.blit(start_button, (10, 430))
            pygame.display.update()

            self.__timer = time.time() - self.__start_time
            hour, minutes, seconds = time.strftime("%Hh %Mm %Ss",
                                                   time.gmtime(self.__timer)).split(' ')
            if '01' in minutes:
                self.__the_client_socket.close()
                return 1, 1

            if entering_username:
                if len(username) < 10:
                    self.draw_text(username, self.font, BLACK, screen, 20, 300)
                else:
                    self.draw_text(username[3:], self.font, BLACK, screen, 20, 300)
            else:
                if len(password) < 10:
                    self.draw_text('*' * len(password), self.font, BLACK, screen, 20, 522)
                else:
                    self.draw_text('*' * len(password[3:]), self.font, BLACK, screen, 20, 522)

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
                print("please")

                self.__the_client_socket.send(details)
                print("details1", details)

                timer = 5
                success = self.receive_data(timer)
                print("Did succeed?", success)

                if success is None:
                    print("Fail")
                    return "Failure"

                else:
                    decrypt = success
                    print(decrypt)

                    if "Success" == decrypt[0]:
                        print("success")
                        return decrypt

                    elif "Failure" == decrypt[0]:
                        print("wrong password or username")
                        return decrypt

            except socket.timeout as e:
                print("exception is", e)
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
           #     print("the full message", full_msg)
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

        except ssl.SSLEOFError:
            print("Server is shutting down")
            message = ["EXIT", 1, private_data]

            full_msg = self.create_message(message)
            self.__the_client_socket.send(full_msg)

            self.__the_client_socket.close()
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
