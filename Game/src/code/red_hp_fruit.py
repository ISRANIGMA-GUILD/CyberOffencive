from fruit import *
from settings import *


class RedHPFruit(Fruit):
    def __init__(self, position: tuple, groups,id) -> None:
        super().__init__(position, groups, f'{BASE_PATH}/graphics/items/fruits/red_hp_fruit/on_map.png', 12, 0,id)

        self.image_paths[ON_MAP] = f'{BASE_PATH}/graphics/items/fruits/red_hp_fruit/on_map.png'
        self.image_paths[ON_HOTBAR] = f'{BASE_PATH}/graphics/items/fruits/red_hp_fruit/on_hotbar.png'
