from spider import *

class RedSpider(Spider):
    def __init__(self, position: tuple, groups, obstacle_sprites, damage_player_func, level) -> None:
        super().__init__('RedSpider', position, groups, obstacle_sprites, damage_player_func, level)