import pygame.display
from level import *
from the_client import *
from creepy import *
from settings import *
import socket
import os
import pickle

IMAGE = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\graphics\\LoginScreen\\menuscreen.png'
BASE_PATH = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\'
LOGIN = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\graphics\\LoginScreen\\login.png'


class Game:
    def __init__(self) -> None:
        pygame.init()
        pygame.mixer.init()

        pygame.font.init()
        self.font = pygame.font.Font(FONT_PATH, 60)

        self.font_chat = pygame.font.Font(FONT_PATH, 40)

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

        self.__locs = [[0, (30, 150)], [1, (30, 100)]]
        self.__previous_details = []

        self.__output_box = pygame.Rect(0, 500, 500, 100)
        self.__input_box = pygame.Rect(0, 600, 200, 50)

        self.__output_o_box = pygame.Rect(0, 500, 500, 100)
        self.__input_o_box = pygame.Rect(0, 600, 200, 50)

        # Blit the text.

        self.__o_width = max(500, 50 + 10)
        self.__i_width = max(500, 50 + 10)

        self.__o_o_width = max(500, 50 + 10)
        self.__o_i_width = max(500, 50 + 10)

        self.__output_box.w = self.__o_width
        self.__input_box.w = self.__i_width

        self.__output_o_box.w = self.__o_o_width
        self.__input_o_box.w = self.__o_i_width
        self.__prev_length = 19

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
                        pygame.display.flip()

                        pygame.display.update()
                        self.clock.tick(FPS)

                        ran = self.network.run()
                        print("DId it really succeed?", ran)
                        if ran == 2:
                            print("what is that new")
                            game_state = "start_menu"

                        elif ran == 1:
                            print("really oh reaaaaally")
                            game_state = "start_menu"

                        else:
                            game_state = "continue"
                            print("Thingy", ran)
                            if len(ran) > 1:
                                items = ran[1][1].split(', ')

                                weapons = ran[1][2].split(', ')
                                #  print(items)
                                if weapons[0] == '1':
                                    self.items["G"] = 1

                                if weapons[1] == '1':
                                    self.items["S"] = 1
                                    self.level.player.inventory.hotbar.insert(Sword((0, 0),
                                                                                    [self.level.visible_sprites]))
                                if items[0] == '1':
                                    self.items["HPF"] = 1
                                    self.level.player.inventory.hotbar.insert(HPFruit((0, 0),
                                                                                    [self.level.visible_sprites]))
                                if items[1] == '1':
                                    self.items["EF"] = 1
                                    self.level.player.inventory.hotbar.insert(EnergyFruit((0, 0),
                                                                                    [self.level.visible_sprites]))

                if game_state == "continue":
                    pygame.display.set_caption("Cyber Offensive")
                    self.new_frame_time = time.time()

                    self.screen.fill((0, 0, 0))
                    self.level.run()

                    prev_loc_other = (0, 0)
                    fps = 1.0 / (self.new_frame_time - self.prev_frame_time)

                    self.prev_frame_time = self.new_frame_time
                    self.text_surface = self.font.render("FPS: " + str(int(fps)), True, (128, 0, 128))

                    self.screen.blit(self.text_surface, (350, 10))
                    other_client = self.network.receive_location()
                    current_loc = self.level.player.get_location()

                    current_status_index = int(self.level.player.frame_index)
                    self.find()

                    list_of_public_details = [current_loc, self.__message, self.level.player.status, 0,
                                              current_status_index]
                    
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
                    #    other_client = pickle.loads(other_client)
                        print("other_client", other_client, type(other_client), other_client[0], other_client[1])

                        if type(other_client) is list or type(other_client) is tuple:
                            print("updating")
                            statuses = other_client[2]
                            status_frame_indexes = other_client[3]

                            self.__other_messages = other_client[1]
                            self.__previous_messages = self.__other_messages
                            locations = other_client[0]

                            prev_loc_other, other_client = self.get_new_locations(locations, prev_loc_other)
                            self.erase_previous(temp_p)

                        #    temp_p = []
                            statuses_updated = []

                            #for i in range(0, len(statuses)):
                            statuses_updated = f'{statuses}_{status_frame_indexes}'

                            p_image = (pygame.image.load(
                                       f'{BASE_PATH}graphics\\player\\{statuses}\\{statuses_updated}.png')
                                       .convert_alpha())

                            if not p_image:
                                pass

                            else:
                               # for i in range(0, len(prev_loc_other)):
                                    player_remote = Tile(position=prev_loc_other,
                                                         groups=[self.level.visible_sprites,
                                                                 self.level.obstacles_sprites],
                                                         sprite_type=PLAYER_OBJECT, surface=p_image)
                                    temp_p = player_remote

                        pygame.display.flip()
                        pygame.display.update()
                        self.clock.tick(FPS)

                    pygame.draw.rect(self.screen, (0, 0, 0), self.__output_box)
                    pygame.draw.rect(self.screen, (0, 255, 0), self.__input_box)
                    pygame.draw.rect(self.screen, (255, 215, 0), self.__output_o_box, 2)
                    pygame.draw.rect(self.screen, (255, 215, 0), self.__input_o_box, 10)
                    pygame.display.flip()

                    if self.__other_messages is not None:

                        if 0 < len(self.__temp_message) <= self.__prev_length:
                            self.draw_text(self.__temp_message, (255, 0, 0), self.screen, 10, 610)
                        else:
                            self.__prev_length += 10
                            self.draw_text(self.__temp_message[self.__prev_length-2:], (255, 0, 0), self.screen, 10, 610)

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

                            if (self.__locs[i][0] != len(self.__other_messages) - 2 or
                                self.__locs[i][0] != len(self.__other_messages) - 1):
                                self.__locs[i][0] += 1
                            #pygame.display.flip()
                        # Blit the input_box rect.

                        pygame.display.flip()

                   # self.__message = None
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

        self.screen = pygame.display.set_mode((1920, 1080), pygame.FULLSCREEN)
        start_button = self.font.render('START', True, (255, 255, 255), (30, 30, 255))
        img = pygame.image.load(IMAGE)

        pygame.transform.scale(img, (1920, 1080))
        self.screen.blit(img, (0, 0))

        print("Image size:", img.get_width(), img.get_height())

        pygame.display.flip()
        input_box = pygame.Rect(860, 550, 200, 100)
        pygame.draw.rect(self.screen, (0, 255, 0), input_box)
        self.screen.blit(start_button, (self.screen.get_width() / 2 - start_button.get_width() / 2,
                                        self.screen.get_height() / 2 + start_button.get_height() / 2))

        pygame.display.update()

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
                #    pygame.display.flip()

            #        pygame.display.update()
             #       self.clock.tick(FPS)

                if event.type == pygame.KEYDOWN or active:
                    if event.key == pygame.K_RETURN:
                        print(message)
                        self.__temp_message = message

                        self.__using_chat = False
                     #   pygame.display.flip()

                   ##     pygame.display.update()
                     #   self.clock.tick(FPS)

                        return message

                    elif event.key == pygame.K_BACKSPACE:
                        message = message[:-1]
                        self.__temp_message = message

                        done = True
                       # pygame.display.flip()

                       ## self.clock.tick(FPS)

                    else:
                        message += event.unicode
                        self.__temp_message = message

                        done = True
                        pygame.display.flip()

                    pygame.display.update()
                    self.clock.tick(FPS)

                end = time.time()
                timer = start - end

                if timer > 0.001:
                    pygame.display.update()
                    self.clock.tick(FPS)

                    return

    def get_new_locations(self, other_client, prev_loc_other):
        """

        :param other_client:
        :param prev_loc_other:
        :return:
        """
        print(other_client)
        other_coordinates = other_client
       # other_coordinates = [(other_client[i][0], other_client[i][1])
       #                      for i in range(0, len(other_client)) if other_client[i] is not None]
      #  prev_loc_other = [other_coordinates[i] for i in range(0, len(other_coordinates))
        #                  if prev_loc_other != other_coordinates[i]]
        prev_loc_other = other_coordinates

        return prev_loc_other, other_coordinates

    def erase_previous(self, temp_p):
        """

        :param temp_p:
        :return:
        """

        if temp_p:
         #   for i in range(0, len(temp_p)):
            self.level.visible_sprites.remove(temp_p)
            self.level.obstacles_sprites.remove(temp_p)

            temp_p.kill()

    def find(self):
        """

        """

        for item_stack in self.level.player.inventory.hotbar.content:
            if len(item_stack) and issubclass(item_stack[0].__class__, Sword):
                self.items["S"] = 1

            if len(item_stack) and issubclass(item_stack[0].__class__, HPFruit):
                self.items["HPF"] = 1

            if len(item_stack) and issubclass(item_stack[0].__class__, EnergyFruit):
                self.items["EF"] = 1

            else:
                pass


def main():
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)

    os.chdir(dname)
    print("Starting Game!!!")

    game = Game()
    game.run()


if __name__ == '__main__':
    main()
