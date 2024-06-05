from settings import *
from melee_weapon import MeleeWeapon


class Axe(MeleeWeapon):
    def __init__(self, position, groups,id) -> None:
        super().__init__(position, groups, 500, 25, 'axe',id)
        self.image_paths[ON_MAP] = f'{BASE_PATH}/graphics/weapons/axe/on_map.png'
        self.image_paths[ON_HOTBAR] = f'{BASE_PATH}/graphics/weapons/axe/on_hotbar.png'
