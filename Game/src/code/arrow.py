from projectile import *


class Arrow(Projectile):
    def __init__(self, angle: float, position: tuple, groups, damage: int) -> None:
        super().__init__(f'{BASE_PATH}/graphics/weapons/bow/arrow.png', angle, position, groups, damage)
