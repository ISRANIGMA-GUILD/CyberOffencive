from settings import *
from melee_weapon import MeleeWeapon


class Sword(MeleeWeapon):
    def __init__(self, position, groups, id) -> None:
        super().__init__(position, groups, 100, 15, 'metal_sword',id)
        self.image_paths[ON_MAP] = f'{BASE_PATH}/graphics/weapons/metal_sword/on_map.png'
        self.image_paths[ON_HOTBAR] = f'{BASE_PATH}/graphics/weapons/metal_sword/on_hotbar.png'
