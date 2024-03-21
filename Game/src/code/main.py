import pygame, sys
from level import *
from settings import *
import time
import os


class Game:
    def __init__(self) -> None:
        pygame.init()
        pygame.font.init()
        self.font = pygame.font.SysFont('Arial Bold', 60)

        self.screen = pygame.display.set_mode((WIDTH, HEIGTH))
        pygame.display.set_caption('Cyber Offensive')
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
            fps = 1.0 / (self.new_frame_time - self.prev_frame_time)
            self.prev_frame_time = self.new_frame_time
            self.text_surface = self.font.render("FPS: " + str(int(fps)), True, (128, 0, 128))
            self.screen.blit(self.text_surface, (50, 10))
            pygame.display.update()
            self.clock.tick(FPS)


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
