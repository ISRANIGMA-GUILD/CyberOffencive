import pygame
from settings import *
from enemy import *

class Goblin(Enemy):
    def __init__(self, position: tuple, groups, obstacle_sprites, damage_player_func, level) -> None:
        super().__init__(GOBLIN, position, groups, obstacle_sprites, damage_player_func, 'goblin_attack', level)