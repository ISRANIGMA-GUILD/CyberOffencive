from enemy import *


class Spider(Enemy):
    def __init__(self, monster_name: str, position: tuple, groups, obstacle_sprites, damage_player_func, level, id) -> None:
        self.rect = pygame.Rect(0,0,0,0)
        super().__init__(monster_name, position, groups, obstacle_sprites, damage_player_func, 'spider_attack', level , id)
