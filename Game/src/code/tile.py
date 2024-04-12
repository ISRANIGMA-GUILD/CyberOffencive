import pygame
from settings import *


class Tile(pygame.sprite.Sprite):
    def __init__(self, position: tuple, groups, sprite_type, surface=pygame.Surface((TILE_WIDTH, TILE_HEIGHT))):
        super().__init__(groups)
        self.sprite_type = sprite_type
        self.image = surface

        if OBJECT == self.sprite_type:
            self.rect = self.image.get_rect(topleft=(position[0], position[1] - TILE_HEIGHT))
        else:
            self.rect = self.image.get_rect(topleft=position)
        self.hitbox = self.rect.inflate(6, -10)
