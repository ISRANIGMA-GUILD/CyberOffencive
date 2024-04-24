import pygame.display
from level import *
from the_client import *
import socket
import os
import pickle
from creepy import *
from settings import *

IMAGE = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\graphics\\LoginScreen\\menuscreen.png'
BASE_PATH = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\'


class Game:
    def __init__(self) -> None:
        pygame.init()
        pygame.mixer.init()

        pygame.font.init()
        self.font = pygame.font.Font(FONT_PATH, 60)

        pygame.event.set_allowed([QUIT, KEYDOWN, KEYUP])
        self.screen = pygame.display.set_mode((WIDTH, HEIGTH), FLAGS, BITS_PER_PIXEL)

        pygame.display.set_caption('Cyber Offensive')
        self.clock = pygame.time.Clock()

        self.level = Level()
        self.network = Client(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))

        self.prev_frame_time = 0
        self.new_frame_time = 0

        self.text_surface = 0
        self.prev_loc = 0

        self.__previous_status = 0
        self.player = CreePy()

        self.__message = ""
        self.weapons = {"Gun": 0, "Sword": 0}

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
                            list_of_details = ["EXIT", 1]

                            other_client = self.network.communicate(list_of_details)
                        pygame.quit()
                        sys.exit()

                if game_state == "start_menu":
                   # self.player.run()

                    self.draw_start_menu()

                    game_state = "game"

                if game_state == "game":
                    loading_screen_image = pygame.image.load(IMAGE).convert()
                    keys = pygame.key.get_pressed()

                    if keys[pygame.K_SPACE]:
                        ran = self.network.run()
                        if ran == 2:
                            game_state = "start_menu"

                        elif ran == 1:
                            break

                        else:
                            game_state = "continue"

                if game_state == "continue":
                    self.__message = ""
                    keys = pygame.key.get_pressed()
                    if keys[pygame.K_m]:
                        self.__message = self.start_chat()
                        if self.__message is None:
                            print("Hello")
                            pass
                        else:
                            print(f"You:", self.__message)

                    pygame.display.set_caption("Cyber Offensive")
                    self.new_frame_time = time.time()
                    self.screen.fill((0, 0, 0))

                    self.level.run()

                    prev_loc_other = (0, 0)
                    fps = 1.0 / (self.new_frame_time - self.prev_frame_time)

                    self.prev_frame_time = self.new_frame_time
                    self.text_surface = self.font.render("FPS: " + str(int(fps)), True, (128, 0, 128))

                    self.screen.blit(self.text_surface, (350, 10))
                    current_loc = self.level.player.get_location()

                    current_status = int(self.level.player.frame_index)
                    self.find()
                #    print(current_status)
                    list_of_details = [current_loc, self.__message, self.level.player.status, 0,
                                       self.weapons, current_status]

                    other_client = self.network.communicate(list_of_details)
                    self.__previous_status = self.level.player.status

                    self.prev_loc = current_loc

                    if other_client is None:
                        pass

                    elif other_client == 1:
                        break

                    elif type(other_client) is bytes:
                        other_client = pickle.loads(other_client)
                        print(other_client)

                        if type(other_client) is list or type(other_client) is tuple:
                            statuses = other_client[2]
                            status_frame_indexes = other_client[4]
                            self.__message = other_client[1]

                            locations = other_client[0]

                            for i in range(0, len(self.__message)):
                                if self.__message[i] is not None or '':
                                    print(f"Client {i+1}:", self.__message[i])

                            prev_loc_other, other_client = self.get_new_locations(locations, prev_loc_other)

                            self.erase_previous(temp_p)
                            temp_p = []

                            statuses_updated = []

                            for i in range(0, len(statuses)):
                                statuses_updated.append(f'{statuses[i]}_{status_frame_indexes[i]}')
                            print(statuses_updated)

                            p_image = [pygame.image.load(
                                f'{BASE_PATH}\\graphics\\player\\{statuses[i]}\\{statuses_updated[i]}.png').convert_alpha()
                                       for i in range(0, len(statuses)) if statuses[i] is not None]

                            if not p_image:
                                pass

                            else:
                                for i in range(0, len(prev_loc_other)):
                                    player_remote = Tile(position=prev_loc_other[i],
                                                         groups=[self.level.visible_sprites, self.level.obstacles_sprites],
                                                         sprite_type=PLAYER_OBJECT, surface=p_image[i])

                                    temp_p.append(player_remote)

                        pygame.display.flip()

                pygame.display.update()
                self.clock.tick(FPS)

            except KeyboardInterrupt:
                if game_state == "continue":
                    list_of_details = ["EXIT", 1]

                    other_client = self.network.communicate(list_of_details)
                pygame.quit()
                sys.exit()

    def draw_start_menu(self):
        """

        """

        self.screen.fill((0, 0, 0))
        font = pygame.font.SysFont('arial', 40)

        start_button = font.render('', True, (255, 255, 255))
        screen = pygame.display.set_mode((1200, 730))

        img = pygame.image.load(IMAGE)
        screen.blit(img, (0, 0))
        pygame.display.flip()

        self.screen.blit(start_button, (self.screen.get_width() / 2 - start_button.get_width() / 2,
                                        self.screen.get_height() / 2 + start_button.get_height() / 2))

        pygame.display.update()

    def start_chat(self):

        username = ""

        font = pygame.font.SysFont('arial', 32)
        entering_username = True

        while True:

            if entering_username:
                if len(username) < 20:
                    self.draw_text(username, font, BLACK, self.screen, 166, 100)
                elif 20 < len(username) < 40:
                    self.draw_text(username[21:], font, BLACK, self.screen, 166, 100)

            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    pygame.quit()
                    sys.exit()
                elif event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_BACKSPACE:
                        if entering_username:
                            if username:
                                username = username[:-1]
                                pygame.display.flip()

                    elif event.key == pygame.K_RETURN:
                        if entering_username:
                            entering_username = False

                            if not entering_username:
                                return username
                            else:
                                return

                    elif event.key == pygame.K_m:
                        return username

                    else:
                        if entering_username:
                            username += event.unicode

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

    def get_new_locations(self, other_client, prev_loc_other):
        """

        :param other_client:
        :param prev_loc_other:
        :return:
        """
        other_coordinates = [(other_client[i][0], other_client[i][1])
                             for i in range(0, len(other_client)) if other_client[i] is not None]

        prev_loc_other = [other_coordinates[i] for i in range(0, len(other_coordinates))
                          if prev_loc_other != other_coordinates[i]]

        return prev_loc_other, other_coordinates

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

        for item_stack in self.level.player.inventory.hotbar.content:
            if len(item_stack) and issubclass(item_stack[0].__class__, Sword):
                self.weapons["Sword"] = 1
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
