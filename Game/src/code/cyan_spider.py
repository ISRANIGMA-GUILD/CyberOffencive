from spider import *


class CyanSpider(Spider):

    def __init__(self, position: tuple, groups, obstacle_sprites, damage_player_func, level) -> None:
        super().__init__('CyanSpider', position, groups, obstacle_sprites, damage_player_func, level)
