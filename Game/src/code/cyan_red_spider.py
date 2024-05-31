from spider import *

class CyanRedSpider(Spider):
    def __init__(self, position: tuple, groups, obstacle_sprites, damage_player_func, level, id) -> None:
        super().__init__('CyanRedSpider', position, groups, obstacle_sprites, damage_player_func, level, id)