import pygame, sys
from level import *
from settings import *
import time
import os


class Game:
    def __init__(self) -> None:
        pygame.init()
        pygame.font.init()
        self.font = pygame.font.Font(FONT_PATH, 60)
        pygame.event.set_allowed([QUIT, KEYDOWN, KEYUP])
        
        self.screen = pygame.display.set_mode((WIDTH, HEIGTH), FLAGS, BITS_PER_PIXEL)
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
            self.screen.fill((0, 0, 0))

            self.level.run()
            print(self.level.player.inventory.hotbar.content, self.level.player.inventory.hotbar.insert(Sword((0, 0), [self.level.visible_sprites])))
            self.find()
            fps = 1.0 / (self.new_frame_time - self.prev_frame_time)

            self.prev_frame_time = self.new_frame_time 
            self.text_surface = self.font.render("FPS: " + str(int(fps)), True, (128, 0, 128))

            self.screen.blit(self.text_surface, (350, 10))
            pygame.display.update()
            self.clock.tick(FPS)

    def find(self):

        for item_stack in self.level.player.inventory.hotbar.content:
            if len(item_stack) and issubclass(item_stack[0].__class__, Sword):
                print("1")
            else:
                pass


def main() -> None:
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    
    print("Starting Game!!!")
    game = Game()
    game.run()


if __name__ == '__main__':
    main()