from ranged_weapon import RangedWeapon

class Bow(RangedWeapon):
    BOW_WIDTH: int = 60
    BOW_HEIGHT: int = 40
    
    def __init__(self, position, groups, groups_for_arrow) -> None:
        super().__init__(position, groups, groups_for_arrow, 120, 10, 'bow')