from projectile import *


class LaserBeam(Projectile):
    def __init__(self, angle: float, position: tuple, groups, damage: int) -> None:
        super().__init__(f'{BASE_PATH}/graphics/enemies/Frenzy/laser.png', angle, position, groups, damage)
