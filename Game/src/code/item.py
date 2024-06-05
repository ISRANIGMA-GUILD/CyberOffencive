import pygame
from settings import *


class Item(pygame.sprite.Sprite):
    def __init__(self, position: tuple, groups, path: str, id) -> None:
        self.rect = pygame.Rect(0,0,0,0)
        super().__init__(groups)
        self.id = id
        self.image = pygame.image.load(path).convert_alpha()
        self.rect = self.image.get_rect(topleft=position)
        self.image_paths = {
            ON_MAP: '',
            ON_HOTBAR: '',
            ON_INVENTORY: '',
        }
