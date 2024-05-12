import pygame
from settings import *
from item import *
from player import *

class Weapon(Item):
    def __init__(self, position, groups, cooldown: int, damage: int, weapon_name: str) -> None:
        self.weapon_name = weapon_name
        self.sprite_type = WEAPON

        super().__init__(position, groups, f'../graphics/weapons/{weapon_name}/on_map.png')

        self.stats : dict  = {
            COOLDOWN: cooldown,
            DAMAGE: damage,
        }


    # TODO: when we finish graphics scale the weapons in the graphics and delete the pygame scaling
    def attack(self, player) -> None:
        self.direction = player.status.split(UNDERSCORE, 1)[0]
        self.full_path = f'../graphics/weapons/{self.weapon_name}/{self.direction}.png' 
        if 'metal_sword' == self.weapon_name:
            if self.direction in [DOWN, UP]:
                self.image = pygame.transform.scale(pygame.image.load(self.full_path).convert_alpha(), (22, 60))
            elif self.direction in [LEFT, RIGHT]:
                self.image = pygame.transform.scale(pygame.image.load(self.full_path).convert_alpha(), (60, 22))
        elif 'axe' == self.weapon_name:
            if self.direction in [DOWN, UP]:
                self.image = pygame.transform.scale(pygame.image.load(self.full_path).convert_alpha(), (40, 60))
            elif self.direction in [LEFT, RIGHT]:
                self.image = pygame.transform.scale(pygame.image.load(self.full_path).convert_alpha(), (60, 40))
        self.rect = self.image.get_rect(center = player.rect.center)

        if RIGHT == self.direction:
            self.rect = self.image.get_rect(midleft = player.rect.midright + pygame.math.Vector2(-10, 3)) # 0, 16
        elif LEFT == self.direction:
            self.rect = self.image.get_rect(midright = player.rect.midleft + pygame.math.Vector2(10, -3)) # 0, 16
        elif DOWN == self.direction:
            self.rect = self.image.get_rect(midtop = player.rect.midbottom + pygame.math.Vector2(-6, -16)) # -10, 0
        elif UP == self.direction:
            self.rect = self.image.get_rect(midbottom = player.rect.midtop + pygame.math.Vector2(10, 10)) # -10, 0