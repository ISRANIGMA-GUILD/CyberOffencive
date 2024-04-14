import pygame
from weapon import *
from settings import *

class MeleeWeapon(Weapon):
    def __init__(self, player, groups) -> None:
        super().__init__(player, groups)