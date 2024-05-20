import pygame
from item import *
from fruit import *
from settings import *

class BlueEnergyFruit(Fruit):
    def __init__(self, position: tuple, groups) -> None:
        super().__init__(position, groups, 'C:\\Program Files (x86)\\Common Files\\CyberOffensive/graphics/items/fruits/blue_energy_fruit/on_map.png', 0, 12)
        
        self.image_paths[ON_MAP] = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive/graphics/items/fruits/blue_energy_fruit/on_map.png'
        self.image_paths[ON_HOTBAR] = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive/graphics/items/fruits/blue_energy_fruit/on_hotbar.png'