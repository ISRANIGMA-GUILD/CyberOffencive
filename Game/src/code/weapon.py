import pygame
from settings import *
from item import *
from player import *


class Weapon(Item):
    def __init__(self, position, groups, cooldown: int, damage: int, weapon_name: str) -> None:
        self.weapon_name = weapon_name
        self.sprite_type = 'weapon'
        
        super().__init__(position, groups, f'../graphics/weapons/{weapon_name}/on_map.png')
                
        self.stats = {
            COOLDOWN: cooldown,
            DAMAGE: damage,
        }

    def attack(self, player) -> None:
        """

        :param player:
        """

        self.direction = player.status.split(UNDERSCORE, 1)[0]
        self.full_path = f'../graphics/weapons/{self.weapon_name}/{self.direction}.png'

        self.image = pygame.image.load(self.full_path).convert_alpha()
        self.rect = self.image.get_rect(center = player.rect.center)
        
        if RIGHT == self.direction:
            self.rect = self.image.get_rect(midleft = player.rect.midright + pygame.math.Vector2(0, 16))

        elif LEFT == self.direction:
            self.rect = self.image.get_rect(midright = player.rect.midleft + pygame.math.Vector2(0, 16))

        elif DOWN == self.direction:
            self.rect = self.image.get_rect(midtop = player.rect.midbottom + pygame.math.Vector2(-10, 0))

        elif UP == self.direction:
            self.rect = self.image.get_rect(midbottom = player.rect.midtop + pygame.math.Vector2(-10, 0))