from ranged_enemy import RangedEnemy


class Frenzy(RangedEnemy):
    def __init__(self, position: tuple, groups, obstacle_sprites, damage_player_func, level) -> None:
        super().__init__('Frenzy', position, groups, obstacle_sprites, damage_player_func, '', level)
