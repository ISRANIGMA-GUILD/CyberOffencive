import pygame.display
from level import *
from the_client import *
from creepy import *
from settings import *
import os
import win32gui
import win32con

IMAGE = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\graphics\\LoginScreen\\menuscreen.png'
BASE_PATH = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\'
LOGIN = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\graphics\\LoginScreen\\login.png'


class Game:
    def __init__(self) -> None:
        pygame.init()
        pygame.mixer.init()
        pygame.font.init()

        #  the_program_to_hide = win32gui.GetForegroundWindow()
        #  win32gui.ShowWindow(the_program_to_hide, win32con.SW_HIDE)

        self.font = pygame.font.Font(FONT_PATH, 60)
        self.font_chat = pygame.font.Font(FONT_PATH, 30)

        pygame.event.set_allowed([QUIT, KEYDOWN, KEYUP])
        self.screen = pygame.display.set_mode((WIDTH, HEIGTH), FLAGS, BITS_PER_PIXEL)

        pygame.display.set_caption('Cyber Offensive')
        self.clock = pygame.time.Clock()

        self.level = Level()
        self.network = Client()

        self.prev_frame_time = 0
        self.new_frame_time = 0

        self.text_surface = 0
        self.prev_loc = 0

        self.__previous_status = 0
        self.player = CreePy()

        self.__message = ""
        self.items = {"G": 0, "S": 0, "HPF": 0, "EF": 0, "RHPF": 0, "BEF": 0}

        self.__using_chat = False
        self.__temp_message = ""

        self.__other_messages = []
        self.__previous_messages = []

        self.__locs = [[0, (10, 500)], [1, (10, 450)]]
        self.__previous_details = []

        self.__output_box = pygame.Rect(0, 500, 500, 100)
        self.__input_box = pygame.Rect(0, 600, 200, 50)

        self.__output_o_box = pygame.Rect(0, 500, 500, 100)
        self.__input_o_box = pygame.Rect(0, 600, 200, 50)

        self.__o_width = max(500, 50 + 10)
        self.__i_width = max(500, 50 + 10)

        self.__o_o_width = max(500, 50 + 10)
        self.__o_i_width = max(500, 50 + 10)

        self.__output_box.w = self.__o_width
        self.__input_box.w = self.__i_width

        self.__output_o_box.w = self.__o_o_width
        self.__input_o_box.w = self.__o_i_width
        self.__prev_length = 19

        self.__remove_item_loc = []
        self.__prev_info = {}

        self.__users = []

    def run(self) -> None:
        """

        """
        game_state = "start_menu"
        temp_p = []

        while True:
            #   v = self.player.get_volume()
            #  v.SetMute(1, None)
            #  v.SetMasterVolumeLevelScalar(1.0, None)
            try:
                for event in pygame.event.get():
                    if pygame.QUIT == event.type:
                        if game_state == "continue":
                            list_of_details = ["EXIT", 1, self.items]
                            self.network.update_server(list_of_details, self.items)

                        pygame.quit()
                        sys.exit()

                if game_state == "start_menu":
                    # self.player.run()

                    self.draw_start_menu()
                    game_state = "game"

                if game_state == "game":
                    keys = pygame.key.get_pressed()

                    if keys[pygame.K_SPACE]:
                        img = pygame.image.load(LOGIN)
                        pygame.transform.scale(img, (1920, 1080))

                        self.screen.blit(img, (0, 0))

                        ran = self.network.run()

                        img = pygame.image.load(LOGIN)
                        pygame.transform.scale(img, (1920, 1080))

                        self.screen.blit(img, (0, 0))

                        print("DId it really succeed?", ran)
                        if ran == 2:
                            print("what is that new")
                            game_state = "start_menu"

                        elif ran == 1:
                            print("really oh reaaaaally")
                            game_state = "start_menu"

                        else:
                            game_state = "continue"
                            pygame.display.set_caption("Cyber Offensive")

                            print("Thingy", ran)

                            if len(ran) > 1:
                                items = ran[1][1].split(', ')

                                weapons = ran[1][2].split(', ')
                                print("the stuff", int(items[0]), weapons, int(items[1]))
                                #  print(items)
                                if weapons[0] == '1':
                                    self.items["G"] = 1

                                if weapons[1] == '1':
                                    self.items["S"] = 1
                                    self.level.player.inventory.hotbar.insert(Sword((0, 0),
                                                                                    [self.level.visible_sprites]))

                                if int(items[0]) > 0:
                                    self.items["HPF"] = int(items[0])
                                    print("HP", self.items["EF"])
                                    for item in range(0, self.items["HPF"]):
                                        self.level.player.inventory.hotbar.insert(HPFruit((0, 0),
                                                                                          [self.level.visible_sprites]))

                                if int(items[1]) > 0:
                                    self.items["EF"] = int(items[1])
                                    print("ENERGY", self.items["EF"])
                                    for item in range(0, self.items["EF"]):
                                        self.level.player.inventory.hotbar.insert(EnergyFruit((0, 0),
                                                                                              [
                                                                                                  self.level.visible_sprites]))

                    pygame.display.flip()

                    pygame.display.update()
                    self.clock.tick(FPS)

                if game_state == "continue":
                    self.new_frame_time = time.time()
                    self.screen.fill((0, 0, 0))

                    self.level.run()
                    fps = 1.0 / (self.new_frame_time - self.prev_frame_time)

                    self.prev_frame_time = self.new_frame_time
                    self.text_surface = self.font.render("FPS: " + str(int(fps)), True, (128, 0, 128))

                    self.screen.blit(self.text_surface, (350, 10))
                    other_client = self.network.receive_location()
                    current_loc = self.level.player.get_location()

                    current_status_index = int(self.level.player.frame_index)
                    self.find()

                    status = f'{self.level.player.status}_{current_status_index}'

                    list_of_public_details = [current_loc, self.__message, status, 0]

                    if self.__previous_details != list_of_public_details:
                        self.network.update_server(list_of_public_details, self.items)
                        self.__previous_details = list_of_public_details

                    self.__previous_status = self.level.player.status
                    self.prev_loc = current_loc
                    print("other client", other_client)
                    if other_client is None:
                        pass

                    elif other_client == 1:
                        print("what the is happening")
                        game_state = "start_menu"

                    else:
                        print("other_client", other_client, type(other_client), other_client[0], other_client[1])

                        if type(other_client) is list or type(other_client) is tuple:
                            print("updating")

                            self.update_users(other_client)
                            self.__prev_info[other_client[3]] = other_client

                            self.__other_messages = other_client[1]
                            print(self.__prev_info, self.__users)

                            if self.__other_messages is not None:
                                self.__previous_messages.append(self.__other_messages)

                            self.erase_previous(temp_p)

                            temp_p = []

                            p_image = [pygame.image.load(
                                       f'{BASE_PATH}graphics\\player\\{self.__prev_info[user][2][0:len(self.__prev_info[user][2])-2]}\\{self.__prev_info[user][2]}.png')
                                       .convert_alpha() for user in self.__users if self.__prev_info[user][2]
                                       is not None]

                            if not p_image:
                                pass

                            else:
                                index = 0
                                for user in self.__users:
                                    player_remote = Tile(position=self.__prev_info[user][0],
                                                         groups=[self.level.visible_sprites,
                                                                 self.level.obstacles_sprites],
                                                         sprite_type=PLAYER_OBJECT, surface=p_image[index])
                                    temp_p.append(player_remote)
                                    index += 1

                    pygame.draw.rect(self.screen, (0, 0, 0), self.__output_box)
                    pygame.draw.rect(self.screen, (0, 255, 0), self.__input_box)

                    pygame.draw.rect(self.screen, (255, 215, 0), self.__output_o_box, 2)
                    pygame.draw.rect(self.screen, (255, 215, 0), self.__input_o_box, 10)

                    if self.__other_messages is not None:

                        if 0 < len(self.__temp_message) <= self.__prev_length:
                            self.draw_text(self.__temp_message, (255, 0, 0), self.screen, 10, 610)
                        else:
                            self.__prev_length += 10
                            self.draw_text(self.__temp_message[self.__prev_length - 2:], (255, 0, 0), self.screen, 10,
                                           610)

                    if self.__previous_messages is not None:
                        for i in range(0, len(self.__locs)):
                            if len(self.__previous_messages) > 0:
                                if len(self.__previous_messages) == 1:
                                    self.draw_text(self.__previous_messages[len(self.__previous_messages) - i - 1],
                                                   (255, 0, 0), self.screen,
                                                   self.__locs[i][1][0], self.__locs[i][1][1])
                                    break

                                else:
                                    self.draw_text(self.__previous_messages[len(self.__previous_messages) - i - 1],
                                                   (255, 0, 0), self.screen,
                                                   self.__locs[i][1][0], self.__locs[i][1][1])
                                if (self.__locs[i][0] != len(self.__previous_messages) - 2 or
                                        self.__locs[i][0] != len(self.__previous_messages) - 1):
                                    self.__locs[i][0] += 1

                    keys = pygame.key.get_pressed()

                    if keys[pygame.K_m] or self.__using_chat:
                        self.__using_chat = True
                        self.__message = self.start_chat()

                        if self.__message is None:
                            pass

                        else:
                            # print(f"You:", self.__message)
                            self.__temp_message = ""
                            self.__using_chat = False
                            self.__prev_length = 19

                    pygame.display.flip()
                    pygame.display.update()
                    self.clock.tick(FPS)

            #  except TypeError:
            #     print("Hold up wait a minute")
            #    if game_state == "continue":
            #        list_of_details = ["EXIT", 1, self.items]
            #        other_client = self.network.communicate(list_of_details, self.items)

            #    game_state = "start_menu"

            except KeyboardInterrupt:
                if game_state == "continue":
                    list_of_details = ["EXIT", 1, self.items]
                    self.network.update_server(list_of_details, self.items)

                pygame.quit()
                sys.exit()

    def draw_start_menu(self):
        """

        """

        self.screen = pygame.display.set_mode((1920, 1080))
        start_button = self.font.render('START', True, (255, 255, 255))
        img = pygame.image.load(IMAGE)

        pygame.transform.scale(img, (1920, 1080))
        self.screen.blit(img, (0, 0))

        print("Image size:", img.get_width(), img.get_height())

        pygame.display.flip()
        input_box = pygame.Rect(860, 550, 200, 100)

        pygame.draw.rect(self.screen, (0, 255, 0), input_box)
        self.screen.blit(start_button, (self.screen.get_width() / 2 - start_button.get_width() / 2,
                                        self.screen.get_height() / 2 + start_button.get_height() / 2))

    #   pygame.display.update()
    # self.clock.tick(FPS)

    def draw_text(self, text, color, surface, x, y):
        """

        :param text:
        :param color:
        :param surface:
        :param x:
        :param y:
        """

        text_tobj = self.font_chat.render(text, 1, color)
        text_rect = text_tobj.get_rect()

        text_rect.topleft = (x, y)
        surface.blit(text_tobj, text_rect)

    def start_chat(self):
        """

        :return:
        """

        message = self.__temp_message
        active = False

        done = False
        start = time.time()

        while not done:
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    done = True

                if event.type == pygame.KEYDOWN or active:
                    if event.key == pygame.K_RETURN:
                        print(message)
                        self.__temp_message = message
                        self.__using_chat = False

                        self.draw_text(self.__temp_message, (255, 0, 0), self.screen, 10, 510)
                        assigned = f"YOU: {self.__temp_message}"

                        self.__previous_messages.append(assigned)
                        return message

                    elif event.key == pygame.K_BACKSPACE:
                        message = message[:-1]
                        self.__temp_message = message

                        done = True

                    else:
                        message += event.unicode
                        self.__temp_message = message

                        done = True
                        # pygame.display.flip()

                #    pygame.display.update()
                # self.clock.tick(FPS)

                end = time.time()
                timer = start - end

                if timer > 0.001:
                    #  pygame.display.update()
                    # self.clock.tick(FPS)

                    return

    def update_users(self, other_client):
        """

        :param other_client:
        """
        print(self.__users, self.__prev_info.keys)
        if self.__users:
            for user in self.__users:
                if user not in list(self.__prev_info.keys()):
                    self.__users.pop(user)

        print("do you exist", other_client[3], self.__prev_info, self.__users)
        for user in list(self.__prev_info.keys()):
            print("what th e fuck", user)
            if user not in self.__users:
                self.__users.append(user)
            else:
                pass

    def erase_previous(self, temp_p):
        """

        :param temp_p:
        :return:
        """

        if temp_p:
            for i in range(0, len(temp_p)):
                self.level.visible_sprites.remove(temp_p[i])
                self.level.obstacles_sprites.remove(temp_p[i])

                temp_p[i].kill()

    def find(self):
        """

        """
        counth = 0
        countf = 0

        for item_stack in self.level.player.inventory.hotbar.content:
            if len(item_stack) and issubclass(item_stack[0].__class__, Sword):
                self.items["S"] = 1
                self.__remove_item_loc.append(self.level.player.get_location())

            for i in range(0, len(item_stack)):
                if len(item_stack) and issubclass(item_stack[i].__class__, HPFruit):
                    counth += 1

                if len(item_stack) and issubclass(item_stack[i].__class__, EnergyFruit):
                    countf += 1

                else:
                    pass

        self.items["HPF"] = counth
        self.items["EF"] = countf


def main():
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    print("Starting Game!!!")

    game = Game()
    game.run()


if __name__ == '__main__':
    main()
