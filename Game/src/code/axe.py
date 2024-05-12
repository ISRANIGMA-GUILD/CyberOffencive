from settings import *
from melee_weapon import MeleeWeapon


class Axe(MeleeWeapon):
    def __init__(self, position, groups) -> None:
        super().__init__(position, groups, 500, 25, 'axe')
        self.image_paths[ON_MAP] = '../graphics/weapons/axe/on_map.png'
        self.image_paths[ON_HOTBAR] = '../graphics/weapons/axe/on_hotbar.png'
