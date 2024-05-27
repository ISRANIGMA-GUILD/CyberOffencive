import pygame
import sys
from level import *
from settings import *
from math import *
import time
import os


class Game:
    def __init__(self) -> None:
        pygame.init()
        pygame.font.init()
        self.font = pygame.font.Font(FONT_PATH, 60)
        pygame.event.set_allowed([QUIT, KEYDOWN, KEYUP])
        
        self.screen = pygame.display.set_mode((WIDTH, HEIGHT), FLAGS, BITS_PER_PIXEL)
        pygame.display.set_caption('Shmulik MMO RPG')
        self.clock = pygame.time.Clock()
        
        self.level = Level()

        self.prev_frame_time = 0
        self.new_frame_time = 0
        self.list_of_l_r_ranges = []
        self.list_of_u_d_ranges = []
        
    def run(self) -> None:
        while True:

            for event in pygame.event.get():
                if pygame.QUIT == event.type:
                    pygame.quit()
                    sys.exit()
                    
            self.new_frame_time = time.time()        
            self.screen.fill((0,0,0))

            self.level.run()
            fps = 1.0 / (self.new_frame_time - self.prev_frame_time)

            self.prev_frame_time = self.new_frame_time
            self.text_surface = self.font.render("FPS: " + str(int(fps)), True, (128, 0, 128))

            if 'left' in self.level.player.status or 'right' in self.level.player.status:
                if ((self.level.player.hitbox.x - self.level.player.get_location()[0],
                     self.level.player.hitbox.y - self.level.player.get_location()[1])
                   not in self.list_of_l_r_ranges):

                    self.list_of_l_r_ranges.append((self.level.player.hitbox.x - self.level.player.get_location()[0],
                                                    self.level.player.hitbox.y - self.level.player.get_location()[1]))
                    print("Up down", self.list_of_u_d_ranges, "\n Left right", self.list_of_l_r_ranges)

            if 'down_idle' in self.level.player.status or 'up_idle' in self.level.player.status:
                if ((self.level.player.hitbox.x - self.level.player.get_location()[0],
                     self.level.player.hitbox.y - self.level.player.get_location()[1])
                        not in self.list_of_u_d_ranges):

                    self.list_of_u_d_ranges.append((self.level.player.hitbox.x - self.level.player.get_location()[0],
                                                    self.level.player.hitbox.y - self.level.player.get_location()[1]))
                    print("Up down", self.list_of_u_d_ranges, "\n Left right", self.list_of_l_r_ranges)

            self.screen.blit(self.text_surface, (350, 10))

            pygame.display.update()
            self.clock.tick(FPS)

def main() -> None:
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    
    print("Starting Game!!!")
    game = Game()
    game.run()


if __name__ == '__main__':
    main()