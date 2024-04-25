import pygame
from item import *
from fruit import *
from settings import *


class EnergyFruit(Fruit):
    def __init__(self, position: tuple, groups) -> None:
        super().__init__(position, groups, '../graphics/items/fruits/energy_fruit/on_map.png', 0, 10)

        self.image_paths[ON_MAP] = '../graphics/items/fruits/energy_fruit/on_map.png'
        self.image_paths[ON_HOTBAR] = '../graphics/items/fruits/energy_fruit/on_hotbar.png'
