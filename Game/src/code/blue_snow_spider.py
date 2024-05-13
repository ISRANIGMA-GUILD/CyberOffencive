from spider import *

class BlueSnowSpider(Spider):
    def __init__(self, position: tuple, groups, obstacle_sprites, damage_player_func, level) -> None:
        super().__init__('BlueSnowSpider', position, groups, obstacle_sprites, damage_player_func, level)