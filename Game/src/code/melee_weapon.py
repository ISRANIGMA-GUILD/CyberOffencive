import pygame
from weapon import *
from settings import *


class MeleeWeapon(Weapon):
    def __init__(self, position, groups, cooldown: int, damage: int, weapon_name: str) -> None:
        super().__init__(position, groups, cooldown, damage, weapon_name)
