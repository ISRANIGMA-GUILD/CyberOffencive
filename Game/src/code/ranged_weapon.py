# TODO in future...

import pygame
from weapon import *


class RangedWeapon(Weapon):
    def __init__(self, player, groups) -> None:
        super().__init__(player, groups)
