import threading
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

        #the_program_to_hide = win32gui.GetForegroundWindow()
      #  win32gui.ShowWindow(the_program_to_hide, win32con.SW_HIDE)

        self.font = pygame.font.Font(FONT_PATH, 60)
        self.font_chat = pygame.font.Font(FONT_PATH, 30)

        pygame.event.set_allowed([QUIT, KEYDOWN, KEYUP])
        self.screen = pygame.display.set_mode((WIDTH, HEIGHT), FLAGS, BITS_PER_PIXEL)

        pygame.display.set_caption('Cyber Offensive')
        self.clock = pygame.time.Clock()

        self.level = Level()
        self.network = Client()

        self.prev_frame_time = 0
        self.new_frame_time = 0

        self.text_surface = 0
        self.prev_loc = 0

        self.__previous_status = 0
     #   self.player = CreePy()

        self.__message = ""
        self.items = {"A": 0, "B": 0, "S": 0, "HPF": 0, "EF": 0, "RHPF": 0, "BEF": 0}

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
        self.__temp_p = []

        self.__keys = pygame.key.get_pressed()
        self.__done = True

        self.__game_state = "start_menu"

        self.__item_locs = []
        self.__enemy_locs = []

        self.__the_enemies = []

        self.__sample_w = ["A", "B", "S", "HPF", "EF", "RHPF", "BEF"]
        self.__sample_e = ["BSS", "BS", "CRS", "CS", "RGS", "RS", "GOB"]

        self.__enemies = []
        self.__weapons = []
        self.__other_client = []

    def run(self) -> None:
        """

        """

        game_lock = threading.Lock()
        div_lock = threading.Lock()
        com_lock = threading.Lock()

        while True:
            #  v = self.player.get_volume()
            #  v.SetMute(1, None)
            #  v.SetMasterVolumeLevelScalar(1.0, None)

            try:
                for event in pygame.event.get():
                    if pygame.QUIT == event.type:
                        if self.__game_state == "continue":
                            list_of_details = ["EXIT", 1, self.items]
                            self.network.update_server(list_of_details, self.items)

                        pygame.quit()
                        sys.exit()

                if self.__game_state == "start_menu":
                    # self.player.run()

                    self.draw_start_menu()
                    self.__game_state = "game"

                if self.__game_state == "game":
                    self.__keys = pygame.key.get_pressed()

                    if self.__keys[pygame.K_SPACE]:
                        img = pygame.image.load(LOGIN)

                        self.screen.blit(img, (0, 0))

                        ran = self.network.run()

                        img = pygame.image.load(LOGIN)

                        self.screen.blit(img, (0, 0))

                     #   print("DId it really succeed?", ran)
                        if ran == 2:
                          #  print("what is that new")
                            self.__game_state = "start_menu"

                        elif ran == 1:
                          #  print("really oh reaaaaally")
                            self.__game_state = "start_menu"

                        else:
                            self.__game_state = "continue"
                            pygame.display.set_caption("Cyber Offensive")

                           # print("Thingy", ran)

                            if len(ran) > 1:
                                items = ran[1][1].split(', ')

                                weapons = ran[1][2].split(', ')
                             #   print("the stuff", int(items[0]), weapons, int(items[1]))
                                #  print(items)
                                if int(weapons[0]) > 0:
                                    self.items["A"] = int(weapons[0])

                                    for item in range(0, self.items["A"]):
                                        self.level.player.inventory.hotbar.insert(Axe((0, 0),
                                                                                        [self.level.visible_sprites]))

                                if int(weapons[1]) > 0:
                                    self.items["B"] = int(weapons[1])

                                    for item in range(0, self.items["B"]):
                                        self.level.player.inventory.hotbar.insert(Bow((0, 0), self.level.visible_sprites,
                                                                                        [self.level.visible_sprites, self.level.attack_sprites]))

                                if int(weapons[2]) > 0:
                                    self.items["S"] = int(weapons[2])

                                    for item in range(0, self.items["S"]):
                                        self.level.player.inventory.hotbar.insert(Sword((0, 0),
                                                                                        [self.level.visible_sprites]))

                                if int(items[0]) > 0:
                                    self.items["HPF"] = int(items[0])

                                    for item in range(0, self.items["HPF"]):
                                        self.level.player.inventory.hotbar.insert(HPFruit((0, 0),
                                                                                          [self.level.visible_sprites]))

                                if int(items[1]) > 0:
                                    self.items["EF"] = int(items[1])
                                    for item in range(0, self.items["EF"]):
                                        self.level.player.inventory.hotbar.insert(EnergyFruit((0, 0),
                                                                                              [self.level.visible_sprites]))

                                if int(items[2]) > 0:
                                    self.items["RHPF"] = int(items[2])

                                    for item in range(0, self.items["RHPF"]):
                                        self.level.player.inventory.hotbar.insert(RedHPFruit((0, 0),
                                                                                              [self.level.visible_sprites]))

                                if int(items[3]) > 0:
                                    self.items["BEF"] = int(items[3])

                                    for item in range(0, self.items["BEF"]):
                                        self.level.player.inventory.hotbar.insert(BlueEnergyFruit((0, 0),
                                                                                              [self.level.visible_sprites]))

                    pygame.display.update()
                    self.clock.tick(FPS)

                if self.__game_state == "continue":

                    threads = self.create_threads(game_lock, com_lock, div_lock)

                    for thread in threads:
                        thread.start()

                    for thread in threads:
                        thread.join()

                    self.__keys = pygame.key.get_pressed()

                    if self.__keys[pygame.K_m] or self.__using_chat:
                        self.__using_chat = True
                        self.__message = self.start_chat()

                        if self.__message is None:
                            pass

                        else:
                            self.__temp_message = ""
                            self.__using_chat = False
                            self.__prev_length = 19

            except KeyboardInterrupt as e:
                print(e)
                if self.__game_state == "continue":
                    list_of_details = ["EXIT", 1, self.items]
                    self.network.update_server(list_of_details, self.items)

                pygame.quit()
                sys.exit()

            except Exception as e:
                print(e)
                if self.__game_state == "continue":
                    list_of_details = ["EXIT", 1, self.items]
                    self.network.update_server(list_of_details, self.items)

                pygame.quit()
                sys.exit()

    def create_threads(self, game_lock, com_lock, div_lock):
        """

        :param game_lock:
        :param com_lock:
        :param div_lock:
        :return:
        """

        game_thread = threading.Thread(target=self.the_game, args=(game_lock,))
        divide_thread = threading.Thread(target=self.divide_data, args=(game_lock,))
        com_thread = threading.Thread(target=self.communication, args=(game_lock,))

        return game_thread, divide_thread, com_thread

    def the_game(self, lock):
        """

        :param lock:
        """

        with lock:
            self.new_frame_time = time.time()
            self.screen.fill((0, 0, 0))

            self.level.run()
            fps = 1.0 / (self.new_frame_time - self.prev_frame_time)

            self.prev_frame_time = self.new_frame_time
            self.text_surface = self.font.render("FPS: " + str(int(fps)), True, (128, 0, 128))

            self.screen.blit(self.text_surface, (350, 10))

    def divide_data(self, lock):

        with lock:

            data1 = self.network.receive_enemies()
            data2 = self.network.receive_items()

            data3 = self.network.receive_location()
            data = [data1, data2, data3]

            self.__enemies, self.__weapons, self.__other_client = self.which_is_it(data)


    def communication(self, lock):
        """

        :param lock:
        """

        with lock:
            current_loc = self.level.player.get_location()
            current_status_index = int(self.level.player.frame_index)
            self.find()

            status = f'{self.level.player.status}_{current_status_index}'
            list_of_public_details = [current_loc, self.__message, status, 0]

            self.__previous_status = self.level.player.status
            self.prev_loc = current_loc

            enemies = self.__enemies

            if enemies:
                [BlueSnowSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                                self.level.obstacles_sprites,
                                self.level.damage_player, self.level) for loc in
                 list(filter(lambda person: "BSS" in person[0], enemies))
                 if loc[0] not in self.__the_enemies]

                [BlueSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                            self.level.obstacles_sprites,
                            self.level.damage_player, self.level) for loc in
                 list(filter(lambda person: "BS" in person[0], enemies)) if loc[0] not in self.__the_enemies]

                [CyanRedSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                               self.level.obstacles_sprites,
                               self.level.damage_player, self.level) for loc in
                 list(filter(lambda person: "CRS" in person[0], enemies)) if loc[0] not in self.__the_enemies]

                [CyanSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                            self.level.obstacles_sprites,
                            self.level.damage_player, self.level) for loc in
                 list(filter(lambda person: "CS" in person[0], enemies)) if loc[0] not in self.__the_enemies]

                [RedGreenSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                                self.level.obstacles_sprites,
                                self.level.damage_player, self.level) for loc in
                 list(filter(lambda person: "RGS" in person[0], enemies)) if loc[0] not in self.__the_enemies]

                [RedSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                           self.level.obstacles_sprites,
                           self.level.damage_player, self.level) for loc in
                 list(filter(lambda person: "RS" in person[0], enemies)) if loc[0] not in self.__the_enemies]

                [Goblin(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                        self.level.obstacles_sprites,
                        self.level.damage_player, self.level) for loc in
                 list(filter(lambda person: "GOB" in person[0], enemies)) if loc[0] not in self.__the_enemies]
                print("e", enemies)

                for loc in enemies:
                    if loc[0] not in self.__the_enemies:
                        self.__the_enemies.append(loc[0])

            elif enemies and 'LEAVE' == enemies[0]:
                self.__game_state = "start_menu"

               #     if loc[0] in self.__enemy_locs:
                   #     self.__enemy_locs[self.__enemy_locs.index(loc[0])]

            weapons = self.__weapons
            if weapons:
                print("w", weapons)
                [Axe(loc[1], [self.level.visible_sprites])
                 for loc in list(filter(lambda person: "A" in person, weapons)) if loc[1] not in self.__item_locs]
                [Bow(loc[1], [self.level.visible_sprites], [self.level.visible_sprites, self.level.attack_sprites])
                 for loc in list(filter(lambda person: "B" in person, weapons)) if loc[1] not in self.__item_locs]

                [Sword(loc[1], [self.level.visible_sprites])
                 for loc in list(filter(lambda person: "S" in person, weapons)) if loc[1] not in self.__item_locs]
                [HPFruit(loc[1], [self.level.visible_sprites])
                 for loc in list(filter(lambda person: "HPF" in person, weapons)) if loc[1] not in self.__item_locs]

                [EnergyFruit(loc[1], [self.level.visible_sprites])
                 for loc in list(filter(lambda person: "EF" in person, weapons)) if loc[1] not in self.__item_locs]
                [RedHPFruit(loc[1], [self.level.visible_sprites])
                 for loc in list(filter(lambda person: "RHPF" in person, weapons)) if loc[1] not in self.__item_locs]

                [BlueEnergyFruit(loc[1], [self.level.visible_sprites])
                 for loc in list(filter(lambda person: "BEF" in person, weapons)) if loc[1] not in self.__item_locs]

                for loc in weapons:
                    if loc[1] not in self.__item_locs:
                        self.__item_locs.append(loc[1])

            elif weapons and "LEAVE" == weapons[0]:
                self.__game_state = "start_menu"

            other_client = self.__other_client

            if self.__previous_details != list_of_public_details:
                s = self.network.update_server(list_of_public_details, self.items)
                if s == 1:
                    self.__game_state = "start_menu"

                else:
                    self.__previous_details = list_of_public_details

            if other_client is None or self.__game_state == "start_menu":
                pass

            elif other_client == 1:
                self.__game_state = "start_menu"

            else:

                if (type(other_client) is list or type(other_client) is tuple) and (len(other_client) == 4):
                    self.update_users()
                    self.__prev_info[other_client[3]] = other_client

                    self.__other_messages = other_client[1]

                    if self.__other_messages is not None:
                        self.__previous_messages.append(self.__other_messages)

                    self.erase_previous()

                    self.__temp_p = []

                    p_image = [pygame.image.load(
                        f'{BASE_PATH}graphics\\player\\{self.__prev_info[user][2][0:len(self.__prev_info[user][2]) - 2]}\\{self.__prev_info[user][2]}.png')
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
                            self.__temp_p.append(player_remote)
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

            pygame.display.update()
            self.clock.tick(FPS)

    def draw_start_menu(self):
        """

        """

        self.screen = pygame.display.set_mode((1920, 1080))
        start_button = self.font.render('START', True, (255, 255, 255))
        img = pygame.image.load(IMAGE)

        self.screen.blit(img, (0, 0))

        pygame.display.update()
        input_box = pygame.Rect(860, 550, 200, 100)

        pygame.draw.rect(self.screen, (0, 255, 0), input_box)
        self.screen.blit(start_button, (self.screen.get_width() / 2 - start_button.get_width() / 2,
                                        self.screen.get_height() / 2 + start_button.get_height() / 2))

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

    def which_is_it(self, data):
        """

        :param data:
        :return:
        """

        enemies = []
        weapons = []
        other_client = []

        for d in data:
            if not d:
                pass

            elif self.is_enemies(d):
                enemies = d[1]

            elif self.is_weapons(d):
                weapons = d[1]

            else:
                other_client = d[1]

        return enemies, weapons, other_client

    def is_enemies(self, data):

        return data[0] == 'e'

    def is_weapons(self, data):

        return data[0] == 'w'

    def start_chat(self):
        """

        :return:
        """

        message = self.__temp_message
        active = False

        self.__done = False
        start = time.time()

        while not self.__done:
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    self.__done = True

                if event.type == pygame.KEYDOWN or active:
                    if event.key == pygame.K_RETURN:
                        self.__temp_message = message
                        self.__using_chat = False

                        self.draw_text(self.__temp_message, (255, 0, 0), self.screen, 10, 510)
                        assigned = f"YOU: {self.__temp_message}"

                        self.__previous_messages.append(assigned)
                        return message

                    elif event.key == pygame.K_BACKSPACE:
                        message = message[:-1]
                        self.__temp_message = message

                        self.__done = True

                    else:
                        message += event.unicode
                        self.__temp_message = message

                        self.__done = True

                end = time.time()
                timer = start - end

                pygame.display.update()
                self.clock.tick(FPS)

                if timer > 0.001:

                    return

    def update_users(self):
        """

        """

        if self.__users:
            for user in self.__users:
                if user not in list(self.__prev_info.keys()):
                    self.__users.pop(user)

        for user in list(self.__prev_info.keys()):
            if user not in self.__users:
                self.__users.append(user)

            else:
                pass

    def erase_previous(self):
        """

        :return:
        """

        if self.__temp_p:
            for i in range(0, len(self.__temp_p)):
                self.level.visible_sprites.remove(self.__temp_p[i])
                self.level.obstacles_sprites.remove(self.__temp_p[i])

                self.__temp_p[i].kill()

    def find(self):
        """

        """
        count_a = 0

        count_s = 0
        count_b = 0

        count_h = 0
        count_f = 0

        count_rf = 0
        count_bef = 0

        for item_stack in self.level.player.inventory.hotbar.content:
            for i in range(0, len(item_stack)):
                if issubclass(item_stack[i].__class__, Axe):
                    count_a += 1

                if issubclass(item_stack[i].__class__, Sword):
                    count_s += 1

                if issubclass(item_stack[i].__class__, Bow):
                    count_b += 1
                #    self.__remove_item_loc.append(self.level.player.get_location())

                if issubclass(item_stack[i].__class__, HPFruit):
                    count_h += 1

                if issubclass(item_stack[i].__class__, EnergyFruit):
                    count_f += 1

                if issubclass(item_stack[i].__class__, RedHPFruit):
                    count_rf += 1

                if issubclass(item_stack[i].__class__, BlueEnergyFruit):
                    count_bef += 1

        self.items["A"] = count_a
        self.items["S"] = count_s

        self.items["B"] = count_b
        self.items["HPF"] = count_h

        self.items["EF"] = count_f
        self.items["RHPF"] = count_rf
        self.items["BEF"] = count_bef


def main():
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    print("Starting Game!!!")

    game = Game()
    game.run()


if __name__ == '__main__':
    main()
