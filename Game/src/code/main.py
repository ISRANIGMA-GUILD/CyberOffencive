import pygame, sys
from level import *
from settings import *
from the_client import *
import socket
import time
import os


IMAGE = 'LoginScreen\\menuscreen.png'

class Game:
    def __init__(self) -> None:
        pygame.init()
        pygame.font.init()

        self.font = pygame.font.SysFont('Arial Bold', 60)
        self.screen = pygame.display.set_mode((WIDTH, HEIGTH))

        pygame.display.set_caption('Cyber Offensive')
        self.clock = pygame.time.Clock()

        self.level = Level()
        self.network = Client(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))

        self.prev_frame_time = 0
        self.new_frame_time = 0

        self.text_surface = 0
        self.prev_loc = 0

    def run(self) -> None:
        """

        """
        game_state = "start_menu"
        while True:
            for event in pygame.event.get():
                if pygame.QUIT == event.type:
                    pygame.quit()
                    sys.exit()

            if game_state == "start_menu":
                self.draw_start_menu()
                game_state = "game"

            if game_state == "game":
                keys = pygame.key.get_pressed()
                if keys[pygame.K_SPACE]:
                    self.network.run()
                    game_state = "continue"

            if game_state == "continue":
                pygame.display.set_caption("Cyber Offensive")
                self.new_frame_time = time.time()
                self.screen.fill((0, 0, 0))

                self.level.run()
                i = 0
                prev_loc_other = (0, 0)
                fps = 1.0 / (self.new_frame_time - self.prev_frame_time)

                self.prev_frame_time = self.new_frame_time
                self.text_surface = self.font.render("FPS: " + str(int(fps)), True, (128, 0, 128))

                self.screen.blit(self.text_surface, (50, 10))
                current_loc = self.level.player.get_location()

                other_client = self.network.communicate(current_loc, self.prev_loc)
                self.prev_loc = current_loc

                if not other_client:
                    pass

                else:

                    other_client = other_client.decode()[2:len(other_client.decode())].split(' ')
                    if other_client[0].isnumeric() and other_client[1].isnumeric():
                        o_x = int(other_client[0])
                        o_y = int(other_client[1])

                        other_coordinates = (o_x, o_y)
                        if prev_loc_other != other_coordinates:
                            print(other_coordinates)
                            prev_loc_other = other_coordinates

                            p = Player(prev_loc_other, self.level.visible_sprites, self.level.obstacles_sprites)
                        pygame.display.flip()

                pygame.display.update()
                self.clock.tick(FPS)

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


def main() -> None:
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)

    # TODO: create client and connect with server

    print("Starting Game!!!")
    game = Game()
    game.run()


if __name__ == '__main__':
    main()
