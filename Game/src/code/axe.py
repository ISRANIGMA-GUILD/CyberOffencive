from settings import *
from melee_weapon import MeleeWeapon

class Axe(MeleeWeapon):
    def __init__(self, position, groups) -> None:
        super().__init__(position, groups, 500, 25, 'axe')
        self.image_paths[ON_MAP] = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive/graphics/weapons/axe/on_map.png'
        self.image_paths[ON_HOTBAR] = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive/graphics/weapons/axe/on_hotbar.png'