import pygame
from item import *
from settings import *

class Fruit(Item):
    def __init__(self, position: tuple, groups, path: str, hp_boost: int, energy_boost: int) -> None:
        super().__init__(position, groups, path)
        self.hp_boost = hp_boost
        self.energy_boost = energy_boost
        
    
    def apply(self, player) -> None:
        player.stats[HEALTH] = min(player.stats[HEALTH] + self.hp_boost, player.max_stats[HEALTH])
        player.stats[ENERGY] = min(player.stats[ENERGY] + self.energy_boost, player.max_stats[ENERGY])