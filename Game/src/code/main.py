import pygame, sys
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
            self.screen.blit(self.text_surface, (350, 10))

            if issubclass(Axe, type):
                subclasses = self.level.player.inventory.hotbar.content.__subclasses__(Axe)
           # else:
             #   subclasses = cls.__subclasses__()
            n = len(self.level.player.inventory.hotbar.content)
            sublists = []

         #   for start in range(n):
            #    for end in range(start + 1, n + 1):
           #         if issubclass(self.level.player.inventory.hotbar.content[start:end].__class__, Axe):
              ##         sublists.append(self.level.player.inventory.hotbar.content[start:end])

         #   print(sublists)

              #  if Axe in it:
                #    print(type(it[0]))
      #      print(m)
         #   print(c)
#
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