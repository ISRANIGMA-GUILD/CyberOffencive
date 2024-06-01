from spider import *

class BlueSpider(Spider):
    def __init__(self, position: tuple, groups, obstacle_sprites, damage_player_func, level, id) -> None:
        super().__init__('BlueSpider', position, groups, obstacle_sprites, damage_player_func, level, id)