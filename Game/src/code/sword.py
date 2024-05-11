import pygame
from settings import *
from melee_weapon import *
from player import *


class Sword(MeleeWeapon):
    def __init__(self, position, groups) -> None:
        super().__init__(position, groups, 100, 15, 'metal_sword')
        self.image_paths[ON_MAP] = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\graphics\\weapons\\metal_sword\\on_map.png'
        self.image_paths[ON_HOTBAR] = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\graphics\\weapons\\metal_sword\\on_hotbar.png'