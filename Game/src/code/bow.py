from ranged_weapon import RangedWeapon


class Bow(RangedWeapon):
    def __init__(self, position, groups, groups_for_arrow) -> None:
        super().__init__(position, groups, groups_for_arrow, 120, 10, 'bow')
