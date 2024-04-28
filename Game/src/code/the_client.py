import pickle
import ssl
from creepy import *
from dnssec_client import *
import socket
import pygame

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

    def __init__(self, the_client_socket: socket):
        self.__client_socket = the_client_socket
        self.__timer = 0

        self.__the_client_socket = None
        self.__start_time = 0

        self.player = CreePy()
        self.__context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # self.v = self.player.get_volume()

    def run(self):
        """

        """

        #  self.player.run()
        count = 0

        server_ip, server_port = self.format_socket()
        res, server_port = self.first_contact(server_ip, server_port)

        while True:
            try:

                self.__the_client_socket.connect((server_ip, server_port))
                break

            except ConnectionRefusedError:
                count += 1
                if count == 3:
                    self.__client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                    self.__the_client_socket.close()
                    server_ip, server_port = self.format_socket()
                    res, server_port = self.first_contact(server_ip, server_port)
                    count = 0
                pass

            except TimeoutError:
                count = 0
                pass

            except OSError:
                self.__client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                self.__the_client_socket.close()
                server_ip, server_port = self.format_socket()
                res, server_port = self.first_contact(server_ip, server_port)
                count = 0

        try:
            if res[Raw].load == b'Accept':

                self.__start_time = time.time()
                details = self.details_entry()

                if details == 1:
                    print("leaving1")
                    message = 'EXIT'.encode()
                    data = [message]

                    if data == 1:
                        print("leaving2")
                        return 1

                    else:
                        self.__the_client_socket.sendall(details)
                        print("leaving3")
                        return 1

                while True:
                    checker = self.check_success(details)

                    if "Success" in checker[0]:
                        print("Nice")
                        return checker

                    elif checker[0] == "Failure":
                        details = self.details_entry()

                    else:
                        print("retry")
                        continue

            else:
                print("TO BAD YOU ARE BANNED!")

        except TypeError:
            print("Leaving the game1")
            message = 'EXIT'.encode()

            self.__the_client_socket.send(message)
            return 1

        except KeyboardInterrupt:
            print("Leaving the game")

            return 1

    def format_socket(self):
        """

        :return:
        """

        self.__context.check_hostname = False
        self.__context.verify_mode = ssl.CERT_NONE

        self.__context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.__context.maximum_version = ssl.TLSVersion.TLSv1_3

        self.__context.set_ecdh_curve('prime256v1')

        self.__the_client_socket = self.__context.wrap_socket(self.__client_socket,
                                                              server_hostname="mad.cyberoffensive.org")

        server_port = self.choose_port()
        server_ip = self.find_ip()

        return server_ip, server_port

    def choose_port(self):
        """

        :return:
        """

        server_port = int(RandShort())

        while True:
            #  self.good_music()

            if server_port < 80 or 1800 <= server_port <= 1900 or 442 < server_port < 501:
                server_port = int(RandShort())

            else:
                break

        return server_port

    def find_ip(self):
        """

        :return:
        """
        while True:
            #   self.good_music()
            server_ip = ServerSearcher().run()

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

    def first_contact(self, server_ip, server_port):
        """
         Get in contact with the server by sending a TCP packet to it
        :param server_ip: The server's ip
        :param server_port: The port the client will connect to
        """

        if server_ip == MY_IP:
            server_mac = get_if_hwaddr(conf.iface)
            layer2 = Ether(src=server_mac, dst=server_mac)

        else:
            server_mac = getmacbyip(server_ip)
            client_mac = get_if_hwaddr(conf.iface)
            layer2 = Ether(src=client_mac, dst=server_mac)

        tcp_packet = (layer2 / IP(src=MY_IP, dst=server_ip) /
                      TCP(sport=RandShort(), dport=server_port) /
                      Raw(load=b'Logged'))
        tcp_packet = tcp_packet.__class__(bytes(tcp_packet))

        sendp(tcp_packet)

        while True:
            # self.good_music()
            vert = sniff(count=1, lfilter=self.filter_tcp, timeout=0.1)
            if not vert:
                sendp(tcp_packet)

            else:

                if vert[0][IP].src != server_ip:
                    print("Send an emergency request")
                    tcp_packet[Raw].load = b'URGENT'

                    tcp_packet[TCP].seq = RandShort()
                    sendp(tcp_packet)

                else:
                    break

        vert.show()
        res = vert[0]

        return res, server_port

    def filter_tcp(self, packets):
        """
         Check if the packet received is a TCP packet
        :param packets: The packet
        :return: If the packet has TCP in it
        """

        return TCP in packets and Raw in packets and \
            (packets[Raw].load == b'Accept' or packets[Raw].load == b'Denied')

    def receive_data(self):
        """
         Dissect the data received from the server
        :return: The data iv, data and tag
        """

        try:
            self.__the_client_socket.settimeout(0.001)
            data_pack = self.__the_client_socket.recv(MAX_MSG_LENGTH)

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

        while True:
            #  self.good_music()
            try:
                user, password = self.login()

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

                self.__the_client_socket.sendall(full_msg)
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
        print(details)
        while True:
            try:
                self.__the_client_socket.send(details)
                success = self.receive_data()

                if not success:
                    print("Fail")
                    pass

                else:
                    decrypt = success
                    print(decrypt)

                    if "Success" in decrypt[0]:
                        print("success")
                        return decrypt

                    elif decrypt[0] == "Failure":
                        print("wrong password or username")
                        return decrypt

            except socket.timeout:
                return

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

    def communicate(self, public_data, private_data):
        """

        :param public_data:
        :param private_data:
        :return:
        """

        self.update_server(public_data, private_data)

        return self.receive_location()

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

                if type(full_msg) is list:
                    for index in range(0, len(full_msg)):
                        message = full_msg[index]
                        self.__the_client_socket.sendall(message)

                else:
                    self.__the_client_socket.sendall(full_msg)

            else:

                full_msg = self.create_message(public_data)
                self.__the_client_socket.sendall(full_msg)

            # if message == 'EXIT':
            # self.__the_client_socket.close()
            # return

        except TypeError:
            return

        except ConnectionResetError:
            print("no no no n")
            message = ["EXIT", 1, private_data]

            full_msg = self.create_message(message)

            self.__the_client_socket.sendall(full_msg)
            self.__the_client_socket.close()

            return

        except ConnectionRefusedError:
            print("Retrying")

        except ConnectionAbortedError:
            print("srsly")
            message = ["EXIT", 1, private_data]
            full_msg = self.create_message(message)

            self.__the_client_socket.sendall(full_msg)
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
            self.__the_client_socket.sendall(full_msg)

            self.__the_client_socket.close()
            return

    def receive_location(self):
        """

        :return:
        """

        try:
            data_recv = self.receive_data()

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

    the_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    client = Client(the_client_socket)
    client.run()


if __name__ == '__main__':
    main()
