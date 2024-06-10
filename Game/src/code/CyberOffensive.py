import threading

import pygame.display
from level import *
from the_client import *
from creepy import *
from settings import *
import hashlib
import ctypes
import sys
import os
import re
import win32gui
import win32con
from blittable import Blittable
from projectile import Projectile
from securety_utils import *

IMAGE = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\graphics\\LoginScreen\\menuscreen.png'
BASE_PATH = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\'
LOGIN = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\graphics\\LoginScreen\\login.png'


class Game:
    def __init__(self) -> None:
        pygame.init()
        pygame.mixer.pre_init(44100, 16, 2, 4096)
        pygame.font.init()

        #the_program_to_hide = win32gui.GetForegroundWindow()
       # win32gui.ShowWindow(the_program_to_hide, win32con.SW_HIDE)

        self.font = pygame.font.Font(FONT_PATH, 60)
        self.font_chat = pygame.font.Font(FONT_PATH, 30)

        pygame.event.set_allowed([QUIT, KEYDOWN, KEYUP])
        self.screen = pygame.display.set_mode((WIDTH, HEIGHT), FLAGS, BITS_PER_PIXEL)

        pygame.display.set_caption('Cyber Offensive')
        self.clock = pygame.time.Clock()

        self.tick = 0
        self.fps = 0
        self.securety = CodeIntegrityChecker()

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

        self.__other_messages = []
        self.__previous_messages = []

        self.__locs = [[0, (10, 300)], [1, (10, 350)]]
        self.__previous_details = []

        self.__output_box = pygame.Rect(0, 200, 500, 200)
        self.__input_box = pygame.Rect(0, 400, 200, 50)

        self.__output_o_box = pygame.Rect(0, 200, 500, 200)
        self.__input_o_box = pygame.Rect(0, 400, 200, 50)

        self.__o_width = max(500, 50 + 10)
        self.__i_width = max(500, 50 + 10)

        self.__o_o_width = max(500, 50 + 10)
        self.__o_i_width = max(500, 50 + 10)

        self.__output_box.w = self.__o_width
        self.__input_box.w = self.__i_width

        self.__output_o_box.w = self.__o_o_width
        self.__input_o_box.w = self.__o_i_width
        self.__prev_length = 19

        self.__using_chat = False
        self.__temp_message = ""
        self.last_chat_update_time = 0
        self.chat_surface = pygame.Surface((self.__output_box.w, self.__output_box.h))
        self.chat_surface_rect = self.chat_surface.get_rect(topleft=self.__output_box.topleft)
        self.enter_key_timer = 0
        self.enter_key_delay = 0.01  # Delay in seconds for Enter key handling

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
        self.__killed_enemies = []

        self.__the_e_id = []
        self.__collected_items_ids_server = []

        self.__collected_items_ids = []
        self.__sample_w = ["A", "B", "S", "HPF", "EF", "RHPF", "BEF"]

        self.__sample_e = ["BSS", "BS", "CRS", "CS", "RGS", "RS", "GOB"]
        self.__enemies = []

        self.__weapons = []
        self.__other_client = []

        self.__timer = 0
        self.__previous = 0

        self.__just_entered = 0
        self.__divide_time = 0

        self.__previously = []
        self.__migrate = 1

        self.__ip = ""
        self.__zone = {}

        self.__possible_spawns = {'Zone1': [(6000, 6000), (15000, 16500), (25000, 8500), (30000, 18500)],
                                  'Zone2': [(40619, 8179),(43500, 9000),(45000, 5000),(55000, 10500)],
                                  'Zone3': [(30000, 34500),(30000, 34000),(35000, 34000),(20000, 33000)],
                                  'Zone4': [(41000, 30000),(43000, 34000),(46000, 35000),(70000, 38000)],
                                  'ZoneBuffer1': [(36600, 6000), (40000, 30600), (39500, 31600), (39600, 40000)],
                                  'ZoneBuffer2': [(24641, 20398), (50000, 20000), (60000, 23000), (65000, 21000)]}

    def run(self) -> None:
        """

        """

        game_lock = threading.Lock()
        div_lock = threading.Lock()
        com_lock = threading.Lock()

        while 1:
            try:
                self.securety.update()

                for event in pygame.event.get():
                    if pygame.QUIT == event.type:
                        if self.__game_state == "continue":
                            list_of_details = ["EXIT", 1, self.items]
                            print("no")
                            self.disconnect_from_server(list_of_details)

                        pygame.quit()
                        sys.exit()

                if self.__game_state == "start_menu":
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

                        if ran == 2:
                            self.__game_state = "start_menu"

                        elif ran == 1:
                            self.__game_state = "start_menu"

                        else:
                            self.__game_state = "continue"
                            pygame.display.set_caption("Cyber Offensive")

                            self.receive_the_many_goods(ran)

                    pygame.display.update()
                    self.clock.tick(FPS)

                if self.__game_state == "continue":
                    if self.__previous == 0:
                        self.__previous = time.time()

                    threads = self.create_threads(game_lock, com_lock, div_lock)

                    for thread in threads:
                        thread.start()

                    for thread in threads:
                        thread.join()
                    
                    original = self.gurgle()
                    self.ungurgle(original)


                    # Handle chat input
                    self.chat_handler()

                    pygame.display.update()
                    self.tick += 1

                    if self.tick % 60 == 0:
                        self.tick = 0
                    self.clock.tick(FPS)
                   # print(self.level.player.get_location())

            except Exception as e:
                print(e)
                if self.__game_state == "continue":
                    list_of_details = ["EXIT", 1, self.items]
                    self.disconnect_from_server(list_of_details)

                pygame.quit()
                sys.exit()

    def receive_the_many_goods(self, ran):
        """

        :param ran:
        """

        if len(ran) > 1 and type(ran[1]) is not dict and not self.contains_dictionary(ran[1]):
            if ran[1][1] is not None:
                self.__zone = ran[2]
                print("The zone", self.__zone)

                loc = self.find_zone_spawn()
                self.level.spawn_the_p(loc)

                items = ran[1][1].split(', ')

                if int(items[0]) > 0:
                    self.items["HPF"] = int(items[0])

                    for item in range(0, self.items["HPF"]):
                        self.level.player.inventory.hotbar.insert(HPFruit((0, 0),
                                                                          [self.level.visible_sprites], "99999"))

                if int(items[1]) > 0:
                    self.items["EF"] = int(items[1])
                    for item in range(0, self.items["EF"]):
                        self.level.player.inventory.hotbar.insert(EnergyFruit((0, 0),
                                                                              [self.level.visible_sprites], "99999"))

                if int(items[2]) > 0:
                    self.items["RHPF"] = int(items[2])

                    for item in range(0, self.items["RHPF"]):
                        self.level.player.inventory.hotbar.insert(RedHPFruit((0, 0),
                                                                             [self.level.visible_sprites], "99999"))

                if int(items[3]) > 0:
                    self.items["BEF"] = int(items[3])

                    for item in range(0, self.items["BEF"]):
                        self.level.player.inventory.hotbar.insert(BlueEnergyFruit((0, 0),
                                                                                  [self.level.visible_sprites],
                                                                                  "99999"))

            if ran[1][2] is not None:
                weapons = ran[1][2].split(', ')

                if int(weapons[0]) > 0:
                    self.items["A"] = int(weapons[0])

                    for item in range(0, self.items["A"]):
                        self.level.player.inventory.hotbar.insert(Axe((0, 0),
                                                                      [self.level.visible_sprites],"99999"))

                if int(weapons[1]) > 0:
                    self.items["B"] = int(weapons[1])

                    for item in range(0, self.items["B"]):
                        self.level.player.inventory.hotbar.insert(Bow((0, 0), self.level.visible_sprites,
                                                                      [self.level.visible_sprites,
                                                                       self.level.attack_sprites],"99999"))

                if int(weapons[2]) > 0:
                    self.items["S"] = int(weapons[2])

                    for item in range(0, self.items["S"]):
                        self.level.player.inventory.hotbar.insert(Sword((0, 0),
                                                                        [self.level.visible_sprites],"99999"))

        else:
            self.__zone = ran[1]
            print("The zone", self.__zone)

            loc = self.find_zone_spawn()
            self.level.spawn_the_p(loc)

    def contains_dictionary(self, lst):
        return any(isinstance(item, dict) for item in lst)

    def find_zone_spawn(self):
        """

        """
        if type(self.__zone) is tuple or type(self.__zone) is list:
            the_zones = [list(self.__zone[0].keys()), list(self.__zone[1].keys())]
            spawner = list(filter(lambda x: (self.__zone[0].get(the_zones[0][0]) <= choice(x)[0] <= self.__zone[0].get(the_zones[0][1])
                            and self.__zone[0].get(the_zones[0][2]) <= choice(x)[1] <= self.__zone[0].get(the_zones[0][3]) or
                            (self.__zone[1].get(the_zones[1][0]) <= choice(x)[0] <= self.__zone[1].get(the_zones[1][1]))
                            and self.__zone[1].get(the_zones[1][2]) <= choice(x)[1] <= self.__zone[1].get(the_zones[1][3]))
                            ,list(self.__possible_spawns.values())))

            spawn = choice(spawner[0])
        else:
            the_zones = list(self.__zone.keys())
            spawner = list(filter(lambda x: self.__zone.get(the_zones[0]) <= choice(x)[0] <= self.__zone.get(the_zones[1])
                           and self.__zone.get(the_zones[2]) <= choice(x)[1] <= self.__zone.get(the_zones[3]),
                           list(self.__possible_spawns.values())))

            spawn = choice(spawner[0])
        return spawn

    def create_threads(self, game_lock, com_lock, div_lock):
        """

        :param game_lock:
        :param com_lock:
        :param div_lock:
        :return:
        """

        game_thread = threading.Thread(target=self.the_game, args=(game_lock,))
        divide_thread = threading.Thread(target=self.divide_data, args=(div_lock,))
        com_thread = threading.Thread(target=self.communication, args=(com_lock,))

        return game_thread, divide_thread, com_thread

    def the_game(self, lock):
        """

        :param lock:
        """

        with lock:
            self.new_frame_time = time.time()
            self.screen.fill((0, 0, 0))

            self.level.run()

            if self.tick % 59 == 0:
                self.fps = 1.0 / (self.new_frame_time - self.prev_frame_time)
            self.prev_frame_time = self.new_frame_time

            self.text_surface = self.font.render("FPS: " + str(int(self.fps)), True, (128, 0, 128))
            self.screen.blit(self.text_surface, (350, 10))

    def divide_data(self, lock):
        """

        :param lock:
        """

        with lock:
            data1 = self.network.receive_stuff()
            data3 = self.network.receive_location()

            data = [data1, data3]
            success_data = self.which_is_it(data)

            if success_data == 1 or success_data == [[[], [], [], []], []]:
                return

            self.__enemies, self.__weapons, self.__killed_enemies, self.__collected_items_ids_server = success_data[0][
                0], success_data[0][1], success_data[0][2], success_data[0][3]
            self.__other_client = success_data[1]

            if self.__other_client:
                if "EXIT" not in self.__other_client[1]:
                    list_of_something = list(filter(lambda x: x[0], self.__previously))

                    if not list(self.__prev_info.keys()):
                        self.__prev_info[self.__other_client[3]] = self.__other_client
                        self.__users.append(self.__other_client[3])

                    elif self.__other_client[3] not in list_of_something:
                        self.__prev_info[self.__other_client[3]] = self.__other_client
                        self.__users.append(self.__other_client[3])

                    else:
                        index = self.__previously.index(list_of_something.index(self.__other_client[3]))
                        self.__prev_info[self.__other_client[3]] = self.__other_client
                        self.__users[index] = self.__other_client[3]

            if data:
                existing_data = list(filter(lambda x: x is not None, data))

                if existing_data:
                    do_i_migrate = list(filter(lambda x: x[0] == 3, existing_data))
                    if 3 in do_i_migrate:
                        print("do i move anyware?", do_i_migrate)

                    if do_i_migrate:
                        self.__ip = do_i_migrate[0][1][1]
                    #    port = do_i_migrate[0][1][1][1]
                     #   print(port)
                        list_of_details = ["EXIT", 1, self.items, "q"]

                        self.disconnect_from_server(list_of_details)
                        self.network = Client()

                        while 1:
                            port = self.network.choose_port()
                            self.network.connect_to_socket(self.__ip, port, self.screen, self.clock, 1)

                            creds = self.network.create_message(do_i_migrate[0][1][2])
                            res = self.network.check_success(creds)

                            if res[0] == "Success":
                                break

                            else:

                                self.disconnect_from_server(list_of_details)
                                self.network = Client()
                        return

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
            if 'attack' in status:
                weapon_type_to_append = ''
                player_active_item = self.level.player.inventory.hotbar.content[self.level.player.inventory.hotbar.active_item_index]
                if player_active_item and len(player_active_item):
                    if issubclass(player_active_item[0].__class__, Sword):
                        weapon_type_to_append = 'S'
                        list_of_public_details = [current_loc, self.__message, status, 0, weapon_type_to_append]
                    elif issubclass(player_active_item[0].__class__, Axe):
                        weapon_type_to_append = 'A'
                        list_of_public_details = [current_loc, self.__message, status, 0, weapon_type_to_append]
                    elif issubclass(player_active_item[0].__class__, Bow):
                        weapon_type_to_append = 'B'
                        if self.level.player.attacking and player_active_item[0].can_shoot():
                            list_of_public_details = [current_loc, self.__message, status, 0, weapon_type_to_append, player_active_item[0].get_angle()]
                        else:
                            list_of_public_details = [current_loc, self.__message, status, 0, weapon_type_to_append]
                else:
                    list_of_public_details = [current_loc, self.__message, status, 0]
            else:
                list_of_public_details = [current_loc, self.__message, status, 0]

            self.__previous_status = self.level.player.status

            self.prev_loc = current_loc
            self.spawn_enemies()

            self.spawn_weapons()
            other_client = self.__other_client        
            self.direction_weapon(other_client)

    
            self.updates_many_updates(list_of_public_details, other_client)
            self.draw_chat()

    def direction_weapon(self, other_client):
        if 5 <= len(other_client) <= 6:
            if 'S' == other_client[4]:
                if 'down' in other_client[2]:
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/metal_sword/down.png', Sword.SWORD_WIDTH, Sword.SWORD_HEIGHT)
                elif 'up' in other_client[2]:    
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/metal_sword/up.png', Sword.SWORD_WIDTH, Sword.SWORD_HEIGHT)
                elif 'right' in other_client[2]:
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/metal_sword/right.png', Sword.SWORD_WIDTH, Sword.SWORD_HEIGHT)
                elif 'left' in other_client[2]:
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/metal_sword/left.png', Sword.SWORD_WIDTH, Sword.SWORD_HEIGHT)
                
            elif 'A' == other_client[4]:
                if 'down' in other_client[2]:
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/axe/down.png', Axe.AXE_WIDTH, Axe.AXE_HEIGHT)
                elif 'up' in other_client[2]:    
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/axe/up.png', Axe.AXE_WIDTH, Axe.AXE_HEIGHT)
                elif 'right' in other_client[2]:
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/axe/right.png', Axe.AXE_WIDTH, Axe.AXE_HEIGHT)
                elif 'left' in other_client[2]:
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/axe/left.png', Axe.AXE_WIDTH, Axe.AXE_HEIGHT)
                
            elif 'B' == other_client[4]:
                if 'down' in other_client[2]:
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/bow/down.png', Bow.BOW_WIDTH, Bow.BOW_HEIGHT)
                elif 'up' in other_client[2]:    
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/bow/up.png', Bow.BOW_WIDTH, Bow.BOW_HEIGHT)
                elif 'right' in other_client[2]:
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/bow/right.png', Bow.BOW_WIDTH, Bow.BOW_HEIGHT)
                elif 'left' in other_client[2]:
                    Blittable(other_client[0], [self.level.blittable_sprites], f'../graphics/weapons/bow/left.png', Bow.BOW_WIDTH, Bow.BOW_HEIGHT)
                
                if len(other_client) == 6:
                    # TODO: use Blittables but for Arrows or Laser Beams
                    Blittable(other_client[0], [self.level.blittable_projectiles_sprites], f'../graphics/weapons/bow/arrow.png', Projectile.PROJECTILE_WIDTH, Projectile.PROJECTILE_HEIGHT, True, other_client[5])


    def spawn_enemies(self):
        """

        """

        enemies = self.__enemies

        if enemies:
            [BlueSnowSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                            self.level.obstacles_sprites,
                            self.level.damage_player, self.level, loc[0]) for loc in
             list(filter(lambda person: "BSS" in person[0], enemies))
             if loc[0] not in self.__the_enemies]

            [BlueSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                        self.level.obstacles_sprites,
                        self.level.damage_player, self.level, loc[0]) for loc in
             list(filter(lambda person: "BS" in person[0], enemies)) if loc[0] not in self.__the_enemies]

            [CyanRedSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                           self.level.obstacles_sprites,
                           self.level.damage_player, self.level, loc[0]) for loc in
             list(filter(lambda person: "CRS" in person[0], enemies)) if loc[0] not in self.__the_enemies]

            [CyanSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                        self.level.obstacles_sprites,
                        self.level.damage_player, self.level, loc[0]) for loc in
             list(filter(lambda person: "CS" in person[0], enemies)) if loc[0] not in self.__the_enemies]

            [RedGreenSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                            self.level.obstacles_sprites,
                            self.level.damage_player, self.level, loc[0]) for loc in
             list(filter(lambda person: "RGS" in person[0], enemies)) if loc[0] not in self.__the_enemies]

            [RedSpider(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                       self.level.obstacles_sprites,
                       self.level.damage_player, self.level, loc[0]) for loc in
             list(filter(lambda person: "RS" in person[0], enemies)) if loc[0] not in self.__the_enemies]

            [Goblin(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                    self.level.obstacles_sprites,
                    self.level.damage_player, self.level, loc[0]) for loc in
             list(filter(lambda person: "GOB" in person[0], enemies)) if loc[0] not in self.__the_enemies]

            [Frenzy(loc[1], [self.level.visible_sprites, self.level.attackable_sprites],
                    self.level.obstacles_sprites,
                    self.level.damage_player, self.level, loc[0]) for loc in
             list(filter(lambda person: "FRE" in person[0], enemies)) if loc[0] not in self.__the_enemies]

            for loc in enemies:
                new_id = re.findall(r'\d+', loc[0])

                if loc[0] not in self.__the_enemies:

                    self.__the_e_id.append(new_id[0])
                    self.__the_enemies.append(loc[0])
                    self.__enemy_locs.append(loc[1])

                elif loc[0] in self.__the_enemies and new_id[0] not in self.__the_e_id:

                    self.__the_enemies.pop(self.__the_e_id.index(new_id[0]))
                    self.__the_e_id.remove(new_id[0])

                else:
                    self.__enemy_locs[self.__the_enemies.index(loc[0])] = loc[1]

            for enemie in self.level.attackable_sprites:
                if enemie.status == 'death' and enemie.id in self.__the_enemies:
                    self.__the_enemies.remove(enemie.id)
                    print("kill", enemie.id)

                    self.network.kill_enemy(enemie.id)
                    
                    self.level.visible_sprites.remove(enemie)
                    self.level.attackable_sprites.remove(enemie)

                    enemie.kill()

                elif enemie.id not in self.__the_enemies:
                    print("kill")
                    self.network.kill_enemy(enemie.id)

                    self.level.visible_sprites.remove(enemie)
                    self.level.attackable_sprites.remove(enemie)

            for enemie in self.level.attackable_sprites:
                if enemie.id in self.__killed_enemies: 
                    self.__the_enemies.remove(enemie.id)
                    self.level.visible_sprites.remove(enemie)

                    self.level.attackable_sprites.remove(enemie)
                    enemie.status = "death"

            for loc in enemies:
                for enemie in self.level.attackable_sprites:
                    if enemie.id == loc[0]:
                        enemie.hitbox.center = loc[1]

        elif enemies and 'LEAVE' == enemies[0]:
            self.__game_state = "start_menu"

    def spawn_weapons(self):
        """

        """

        weapons = self.__weapons
        item_ids_server = [item[0] for item in weapons]

        hotbar_item_ids = [item for item in self.level.player.inventory.hotbar.get_ids()]

        whitelist = [Axe, Bow, Sword, HPFruit, EnergyFruit, RedHPFruit, BlueEnergyFruit]
        
        items_ = [item for item in self.level.visible_sprites if type(item) in whitelist and item not in self.level.picked_up and item.id not in hotbar_item_ids]
        items_ids = [item.id for item in self.level.visible_sprites if type(item) in whitelist and item not in self.level.picked_up and item.id not in hotbar_item_ids]

        if weapons:
            [Axe(loc[1], [self.level.visible_sprites],loc[0])
             for loc in list(filter(lambda person: "A" in person[0], weapons)) if loc[0] not in [item.id for item in self.level.picked_up] and loc[0] not in items_ids]
            
            [Bow(loc[1], [self.level.visible_sprites], [self.level.visible_sprites, self.level.attack_sprites],loc[0])
             for loc in list(filter(lambda person: "B" in person[0], weapons)) if loc[0] not in [item.id for item in self.level.picked_up] and loc[0] not in items_ids]

            [Sword(loc[1], [self.level.visible_sprites],loc[0])
             for loc in list(filter(lambda person: "S" in person[0], weapons)) if loc[0] not in [item.id for item in self.level.picked_up] and loc[0] not in items_ids]
            [HPFruit(loc[1], [self.level.visible_sprites],loc[0])
             for loc in list(filter(lambda person: "HPF" in person[0], weapons)) if loc[0] not in [item.id for item in self.level.picked_up] and loc[0] not in items_ids]

            [EnergyFruit(loc[1], [self.level.visible_sprites],loc[0])
             for loc in list(filter(lambda person: "EF" in person[0], weapons)) if loc[0] not in [item.id for item in self.level.picked_up] and loc[0] not in items_ids]
            [RedHPFruit(loc[1], [self.level.visible_sprites],loc[0])
             for loc in list(filter(lambda person: "RHPF" in person[0], weapons)) if loc[0] not in [item.id for item in self.level.picked_up] and loc[0] not in items_ids]

            [BlueEnergyFruit(loc[1], [self.level.visible_sprites],loc[0])
             for loc in list(filter(lambda person: "BEF" in person[0], weapons)) if loc[0] not in [item.id for item in self.level.picked_up] and loc[0] not in items_ids]

            for item in items_:
                if item.id in self.__collected_items_ids_server:
                    self.level.visible_sprites.remove(item)

            for item in self.level.picked_up:
                self.__collected_items_ids.append(item.id)
                self.level.picked_up.remove(item)

                print("picked up item", item.id)
                self.network.picked_up(item.id)

                item.id = "99999"

        elif weapons and "LEAVE" == weapons[0]:
            self.__game_state = "start_menu"

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

    def draw_chat(self):

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

    def updates_many_updates(self, list_of_public_details, other_client):
        """

        :param list_of_public_details:
        :param other_client:
        """
        print("how far", other_client)
        if self.__previous_details != list_of_public_details or self.__just_entered == 0:  # or self.__timer >= 0.02:
            print(self.level.player.get_location())
            s = self.network.update_server(list_of_public_details, self.items)
            self.__previous_details = list_of_public_details

            if s == 1:
                self.__game_state = "start_menu"

            self.__just_entered = 1

        if other_client is None or self.__game_state == "start_menu":
            if self.__users:
                self.update_users()
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

        elif other_client == 1:
            self.__game_state = "start_menu"

        else:
            if (type(other_client) is list or type(other_client) is tuple) and (len(other_client) == 4):
                self.update_users()
                self.__prev_info[other_client[3]] = other_client

                self.__other_messages = other_client[1]

                if self.__other_messages is not None:
                    self.__previous_messages.append(f'{other_client[3]}: {self.__other_messages}')

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

    def draw_text(self, text, color, surface, x, y):
        """
        """

        text_tobj = self.font_chat.render(text, 1, color)
        text_rect = text_tobj.get_rect()

        text_rect.topleft = (x, y)
        surface.blit(text_tobj, text_rect)

    def which_is_it(self, data):
        """
        """

        stuff = [[], [], [], []]
        other_client = []

        for d in data:
            if type(d) is int:
                print("what the fuck")
                self.__game_state = "start_menu"

                list_of_details = ["EXIT", 1, self.items]
                self.network.update_server(list_of_details, self.items)
                return 1

            elif d is None:
                pass

            elif self.is_enemies(d):
                stuff = [d[1], d[2], d[3], d[4]]

            else:
                other_client = d

        return stuff, other_client

    def is_enemies(self, data):

        return data[0] == "eeee"

    def chat_handler(self):
        """Handles chat input and updates the chat UI."""

        # Check if chat is active
        self.__keys = pygame.key.get_pressed()
        if self.__keys[pygame.K_m] or self.__using_chat:
            self.__using_chat = True
            self.level.using_chat = True

            self._handle_chat_input()
        else:
            self.level.using_chat = False

        current_time = time.time()
        if current_time - self.last_chat_update_time > 0.05:
            self.draw_chat_ui()
            self.last_chat_update_time = current_time

    def _handle_chat_input(self):
        """Handles chat input non-blocking."""

        # Check for chat input events
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()

            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_RETURN:
                    self.enter_key_timer = time.time()
                elif event.key == pygame.K_BACKSPACE:
                    if self.__temp_message:
                        self.__temp_message = self.__temp_message[:-1]
                else:
                    self.__temp_message += event.unicode

                self.chat_surface.fill((0, 0, 0))
                self.draw_chat_messages(self.chat_surface)

        # Handle Enter key press with a timer
        if self.enter_key_timer:
            if time.time() - self.enter_key_timer >= self.enter_key_delay:
                self.__temp_message = self.__temp_message.strip()
                if self.__temp_message:
                    self.__message = self.__temp_message
                    self.__using_chat = False
                    self.__temp_message = ""
                    assigned = f"YOU: {self.__message}"
                    self.__previous_messages.append(assigned)
                    self.enter_key_timer = 0  # Reset timer
                    self.draw_chat_ui()  # Update UI

    def draw_chat_ui(self):
        """Draws the chat UI on the screen."""

        pygame.draw.rect(self.screen, (0, 255, 0), self.__input_box)

        self.screen.blit(self.chat_surface, self.chat_surface_rect)

    def draw_chat_messages(self, surface):
        """Draws chat messages on the specified surface."""

        pygame.draw.rect(surface, (0, 0, 0), self.__output_box)
        pygame.draw.rect(surface, (255, 215, 0), self.__output_o_box, 2)

        if self.__other_messages is not None:
            if 0 < len(self.__temp_message) <= self.__prev_length:
                self.draw_text(self.__temp_message, (255, 0, 0), surface, 10, 610)
            else:
                self.__prev_length += 10
                self.draw_text(self.__temp_message[self.__prev_length - 2:], (255, 0, 0), surface, 10, 610)

        if self.__previous_messages is not None:
            for i in range(0, len(self.__locs)):
                if len(self.__previous_messages) > 0:
                    if len(self.__previous_messages) == 1:
                        self.draw_text(self.__previous_messages[len(self.__previous_messages) - i - 1],
                                       (255, 0, 0), surface,
                                       self.__locs[i][1][0], self.__locs[i][1][1])
                        break
                    else:
                        self.draw_text(self.__previous_messages[len(self.__previous_messages) - i - 1],
                                       (255, 0, 0), surface,
                                       self.__locs[i][1][0], self.__locs[i][1][1])
                    if (self.__locs[i][0] != len(self.__previous_messages) - 2 or
                            self.__locs[i][0] != len(self.__previous_messages) - 1):
                        self.__locs[i][0] += 1

    def update_users(self):
        """

        """

        if self.__users:
            for user in self.__users:
                if user not in list(self.__prev_info.keys()) or user not in list(filter(lambda x: x[0], self.__previously)):
                    self.__users.remove(user)

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

    def disconnect_from_server(self, list_of_details):
        """

        """

        while True:
            try:
                ack = self.network.receive_ack()
                self.network.update_server(list_of_details, self.items)
                if ack:
                    if "OK" in ack:
                        self.network.close_connection()
                        break

            except Exception as e:
                print("EXITED BECAUSE?", e)
                break

    def gurgle(self):
        """
        makes all values random
        """
        original_player = self.level.player.gurgle()


        return original_player

    def ungurgle(self, original_player):
        """

        """
        self.level.player.ungurgle(original_player)


def main():
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    print("Starting Game!!!")

    game = Game()
    game.run()


if __name__ == '__main__':
    main()
