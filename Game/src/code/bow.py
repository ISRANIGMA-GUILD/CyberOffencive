from ranged_weapon import RangedWeapon

class Bow(RangedWeapon):
    def __init__(self, position, groups, groups_for_arrow, id) -> None:
        super().__init__(position, groups, groups_for_arrow, 120, 10, 'bow',id)