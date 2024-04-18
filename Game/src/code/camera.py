import pygame
from settings import *

BASE_PATH = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\'


class YSortCameraGroup(pygame.sprite.Group):

    def __init__(self) -> None:
        super().__init__()
        self.display_surface = pygame.display.get_surface()
        self.half_width = pygame.display.get_surface().get_size()[0] // 2

        self.half_height = pygame.display.get_surface().get_size()[1] // 2
        self.offset = pygame.math.Vector2()

        self.floor_surface = pygame.image.load(f'{BASE_PATH}graphics\\tilemap\\ground.png').convert()
        self.floor_rect = self.floor_surface.get_rect(topleft=(0, 0))

    def custom_draw(self, player) -> None:
        self.offset.x = player.rect.centerx - self.half_width
        self.offset.y = player.rect.centery - self.half_height

        floor_offset_position = self.floor_rect.topleft - self.offset
        self.display_surface.blit(self.floor_surface, floor_offset_position)

        for sprite in sorted(self.sprites(), key=lambda sprite: sprite.rect.centery):
            offset_position = sprite.rect.topleft - self.offset
            self.display_surface.blit(sprite.image, offset_position)    
        