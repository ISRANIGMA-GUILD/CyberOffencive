from fruit import *
from settings import *


class EnergyFruit(Fruit):
    def __init__(self, position: tuple, groups,id) -> None:
        self.rect = pygame.Rect(0,0,0,0)
        super().__init__(position, groups, f'{BASE_PATH}/graphics/items/fruits/energy_fruit/on_map.png', 0, 10,id)
        
        self.image_paths[ON_MAP] = f'{BASE_PATH}/graphics/items/fruits/energy_fruit/on_map.png'
        self.image_paths[ON_HOTBAR] = f'{BASE_PATH}/graphics/items/fruits/energy_fruit/on_hotbar.png'