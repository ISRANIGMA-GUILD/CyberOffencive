import pygame
from settings import *
from enemy import *

class Spider(Enemy):
    def __init__(self, monster_name:str, position: tuple, groups, obstacle_sprites, damage_player_func, level) -> None:
        super().__init__(monster_name, position, groups, obstacle_sprites, damage_player_func, 'spider_attack', level)