from spider import *


class RedGreenSpider(Spider):
    def __init__(self, position: tuple, groups, obstacle_sprites, damage_player_func, level) -> None:
        super().__init__('RedGreenSpider', position, groups, obstacle_sprites, damage_player_func, level)