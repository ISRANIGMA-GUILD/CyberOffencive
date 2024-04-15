import pygame
from settings import *


class Weapon(pygame.sprite.Sprite):
    def __init__(self, player, groups) -> None:
        super().__init__(groups)
        
        if player.active_item not in list(WEAPON_DATA.keys()):
            self.kill()
            return
        
        self.direction = player.status.split(UNDERSCORE, 1)[0]
        self.full_path = f'../graphics/weapons/{player.active_item}/{self.direction}.png'
        
        self.image = pygame.image.load(self.full_path).convert_alpha()
        self.rect = self.image.get_rect(center=player.rect.center)
        
        if RIGHT == self.direction:
            self.rect = self.image.get_rect(midleft=player.rect.midright + pygame.math.Vector2(0, 16))

        elif LEFT == self.direction:
            self.rect = self.image.get_rect(midright=player.rect.midleft + pygame.math.Vector2(0, 16))

        elif DOWN == self.direction:
            self.rect = self.image.get_rect(midtop=player.rect.midbottom + pygame.math.Vector2(-10, 0))

        elif UP == self.direction:
            self.rect = self.image.get_rect(midbottom=player.rect.midtop + pygame.math.Vector2(-10, 0))
