from creepy import *
from client_handshake import *
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
PARAM_LIST = {"0": 0x0303, "1": 0x16, "2": 0x15, "3": 0x14, "4": 0x1}
SECP = [0x6a6a, 0x001d, 0x0017, 0x0018]
SIGNATURE_ALGORITHIM = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
KEY = {}
FONT = pygame.font.Font(None, 42)
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
GRAY = (200, 200, 200)
IMAGE = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\Graphics\\LoginScreen\\login.png'


class Client:

    def __init__(self, the_client_socket: socket):
        self.__the_client_socket = the_client_socket
        self.__timer = 0

        self.__start_time = 0
        self.player = CreePy()

       # self.v = self.player.get_volume()

    def run(self):
        """

        """

        try:
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
                        server_ip, server_port = self.format_socket()
                        res, server_port = self.first_contact(server_ip, server_port)
                        count = 0
                    pass

                except TimeoutError:
                    count = 0
                    pass

                except OSError:
                    server_ip, server_port = self.format_socket()
                    res, server_port = self.first_contact(server_ip, server_port)
                    count = 0

            try:
                if res[Raw].load == b'Accept':
                    if 'encryption' not in KEY.keys():
                        self.initialize_handshakes(server_ip, server_port)

                        if None not in KEY.values():
                            self.__start_time = time.time()
                            encryption_key, auth = KEY['encryption'][0], KEY['encryption'][1]
                            try:
                                details = self.details_entry(encryption_key, auth)

                                if details == 1:
                                    message = 'EXIT'.encode()
                                    data = [self.encrypt_data(encryption_key, message, auth)]

                                    full_msg = self.create_message(data)
                                    self.__the_client_socket.send(bytes(full_msg[TLS]))

                                    return 1

                                while True:

                                    checker = self.check_success(encryption_key, details, auth)
                                    if "Success" in checker[0]:
                                        print("Nice")
                                        return checker

                                    elif checker[0] == "Failure":
                                        details = self.details_entry(encryption_key, auth)

                                    else:
                                        print("retry")
                                        continue

                            except TypeError:
                                print("Leaving the game")
                                message = 'EXIT'.encode()

                                data = [self.encrypt_data(encryption_key, message, auth)]
                                full_msg = self.create_message(data)

                                self.__the_client_socket.send(bytes(full_msg[TLS]))
                                return 1

                            except KeyboardInterrupt:
                                print("Leaving the game")
                                message = 'EXIT'.encode()

                                data = [self.encrypt_data(encryption_key, message, auth)]
                                full_msg = self.create_message(data)

                                self.__the_client_socket.send(bytes(full_msg[TLS]))
                                return 1

                else:
                    print("TO BAD YOU ARE BANNED!")

            except TypeError:
                print("Leaving the game")
                return 1

        except TypeError:
            print("Leaving the game")
            return 1

        except ConnectionRefusedError:
            print("Connection refused check your internet")

        except KeyboardInterrupt:
            print("Leaving the game")

            return 1

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
            vert = sniff(count=1, lfilter=self.filter_tcp, timeout=0.01)
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

    def initialize_handshakes(self, server_ip, server_port):
        """

        :param server_ip:
        :param server_port:
        """

        try:
            handshake = ClientHandshake(self.__the_client_socket, server_ip, server_port)
            KEY['encryption'] = handshake.run()

            if 'encryption' not in KEY.keys():
                return

            else:
                if not KEY['encryption']:
                    return

                else:
                    return

        except KeyboardInterrupt:
            print("refused to play")

        except ConnectionRefusedError:
            pass

    def recieve_data(self):
        """
         Dissect the data received from the server
        :return: The data iv, data and tag
        """

        try:
            data_pack = self.__the_client_socket.recv(MAX_MSG_LENGTH)

            if not data_pack:
                return

            else:
                data_pack = TLS(data_pack)
                data = data_pack[TLS][TLSApplicationData].data
                data_iv = data[:12]

                data_tag = data[len(data) - 16:len(data)]
                data_c_t = data[12:len(data) - 16]

            return data_iv, data_c_t, data_tag

        except IndexError:
            return

        except socket.timeout:
            return

        except struct.error:
            return

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

    def decrypt_data(self, key, associated_data, iv, ciphertext, tag):
        """
         Decrypt the data recieved by the client
        :param key: The server encryption key
        :param associated_data: The data associated with the message
        :param iv: The iv
        :param ciphertext: The encrypted data
        :param tag: The encryption tag
        :return: The decrypted data
        """

        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(associated_data)

        return decryptor.update(ciphertext) + decryptor.finalize()

    def create_message(self, some_data):
        """
         Turn the data into a proper message
        :param some_data: The data parts
        :return: The full data message
        """

        if type(some_data) is not list:
            full_data = some_data[0] + some_data[1] + some_data[2]
            data_packet = TLS(msg=TLSApplicationData(data=full_data))

            data_message = data_packet
            data_message = data_message.__class__(bytes(data_message))

        else:
            data_pack_list = []

            for i in range(0, len(some_data)):
                first_data = some_data[i][0] + some_data[i][1] + some_data[i][2]
                data_packet = TLS(msg=TLSApplicationData(data=first_data))

                data_packet = data_packet.__class__(bytes(data_packet))
                data_pack_list.append(data_packet)

            return data_pack_list

        return data_message

    def details_entry(self, key, auth):
        """

         Turn the data into a proper message
        :param key: The key
        :param auth: The authenticator
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
                    credentials = pickle.dumps((user, password))

                    encrypted_credentials = self.encrypt_data(key, credentials, auth)
                    data = encrypted_credentials

                    pack = self.create_message(data)
                    return pack

            except KeyboardInterrupt:
                message = 'EXIT'.encode()
                print(message)

                data = [self.encrypt_data(key, message, auth)]
                full_msg = self.create_message(data)

                self.__the_client_socket.send(bytes(full_msg[TLS]))
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

    def check_success(self, key, details, auth):
        """

        :param key:
        :param details:
        :param auth:
        :return:
        """

     #   self.good_music()
        while True:
            try:
                self.__the_client_socket.send(bytes(details[TLS]))
                success = self.recieve_data()

                if not success:
                    print("Fail")
                    pass

                else:
                    decrypt = pickle.loads(self.decrypt_data(key, auth, success[0], success[1], success[2]))
                    print(decrypt)

                    if "Success" in decrypt[0]:
                        print("success")
                        return decrypt

                    elif decrypt[0] == "Failure":
                        print("wrong password or username")
                        return decrypt

            except socket.timeout:
                return

    def is_there_an_alert(self, message):
        """

        :param message:
        :return:
        """

        return TLS in message and TLSAlert in message

    def send_alert(self):
        """

        :return:
        """

        alert = TLS(msg=TLSAlert(level=2, descr=40))
        alert = alert.__class__(bytes(alert))

        return alert

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
        key, auth = KEY['encryption'][0], KEY['encryption'][1]

        return self.receive_location(key, auth)

    def update_server(self, public_data, private_data):
        """

        :param public_data:
        :param private_data:
        :return:
        """

       # self.good_music()
        if 1 not in KEY:
            key, auth = KEY['encryption'][0], KEY['encryption'][1]
            try:
                if public_data[0] == "EXIT":
                    print("leaving")
                    after = [public_data[0], public_data[1], public_data[2]]
                    after = pickle.dumps(after)

                    data = [self.encrypt_data(key, after, auth)]
                    full_msg = self.create_message(data)

                    if type(full_msg) is list:
                        for index in range(0, len(full_msg)):
                            message = full_msg[index]
                            self.__the_client_socket.send(bytes(message[TLS]))

                    else:
                        self.__the_client_socket.send(bytes(full_msg[TLS]))

                else:
                    player_data = [public_data[0], public_data[1], public_data[2], public_data[3], public_data[4]]
                    player_data = pickle.dumps(player_data)

                    p_data = [self.encrypt_data(key, player_data, auth)]
                    full_msg = self.create_message(p_data)

                    if type(full_msg) is list:
                        for index in range(0, len(full_msg)):
                            message = full_msg[index]
                            self.__the_client_socket.send(bytes(message[TLS]))

                    else:
                        self.__the_client_socket.send(bytes(full_msg[TLS]))

                   # if message == 'EXIT':
                       # self.__the_client_socket.close()
                        #return

            except ConnectionResetError:
                message = ["EXIT", 1, private_data]
                message = pickle.dumps(message)

                data = [self.encrypt_data(key, message, auth)]
                full_msg = self.create_message(data)

                self.__the_client_socket.send(bytes(full_msg[TLS]))
                self.__the_client_socket.close()

                return

            except ConnectionRefusedError:
                print("Retrying")

            except ConnectionAbortedError:
                message = ["EXIT", 1, private_data]
                message = pickle.dumps(message)

                data = [self.encrypt_data(key, message, auth)]
                full_msg = self.create_message(data)

                self.__the_client_socket.send(bytes(full_msg[TLS]))
                self.__the_client_socket.close()

                return

            except pickle.PickleError:
                return

            except socket.timeout:
                return

            except KeyboardInterrupt:
                print("Server is shutting down")
                message = ["EXIT", 1, private_data]

                message = pickle.dumps(message)
                data = [self.encrypt_data(key, message, auth)]

                full_msg = self.create_message(data)
                self.__the_client_socket.send(bytes(full_msg[TLS]))

                self.__the_client_socket.close()
                return

    def receive_location(self, key, auth):
        """

        :param key:
        :param auth:
        :return:
        """

        try:
            self.__the_client_socket.settimeout(0.01)
            data_recv = self.recieve_data()

            if not data_recv:
                pass

            else:
                return self.decrypt_data(key, auth, data_recv[0], data_recv[1], data_recv[2])

        except socket.timeout:
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
