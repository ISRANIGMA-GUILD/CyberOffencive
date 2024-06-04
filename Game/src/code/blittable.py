import pygame
from settings import *

class Blittable(pygame.sprite.Sprite):
    def __init__(self, position: tuple, groups, path: str, width: int, height: int) -> None:
        super().__init__(groups)

        size = (width, height)
        if 'left' in path or 'right' in path:
            size = (height, width)
                
        self.image = pygame.transform.scale(pygame.image.load(path).convert_alpha(), size)
        player_rect = pygame.Rect(position, (57, 77))
        
        if 'right' in path:
            self.rect = self.image.get_rect(midleft = player_rect.midright + pygame.math.Vector2(-10, 3)) # 0, 16
        elif 'left' in path:
            self.rect = self.image.get_rect(midright = player_rect.midleft + pygame.math.Vector2(10, -3)) # 0, 16
        elif 'down' in path:
            self.rect = self.image.get_rect(midtop = player_rect.midbottom + pygame.math.Vector2(-6, -16)) # -10, 0
        elif 'up' in path:
            self.rect = self.image.get_rect(midbottom = player_rect.midtop + pygame.math.Vector2(10, 10)) # -10, 0