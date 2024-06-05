from weapon import *


class MeleeWeapon(Weapon):
    def __init__(self, position, groups, cooldown: int, damage: int, weapon_name: str,id) -> None:
        super().__init__(position, groups, cooldown, damage, weapon_name,id)
