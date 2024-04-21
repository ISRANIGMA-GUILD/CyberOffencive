#TODO in future...

import pygame
from weapon import *

class RangedWeapon(Weapon):
    def __init__(self, player, groups, cooldown: int, damage: int, path: str) -> None:
        super().__init__(player, groups, cooldown, damage, path)