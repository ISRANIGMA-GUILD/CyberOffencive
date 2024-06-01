from spider import *

class BasicSpider(Spider):
    def __init__(self, position: tuple, groups, obstacle_sprites, damage_player_func, level, id) -> None:
        super().__init__('BasicSpider', position, groups, obstacle_sprites, damage_player_func, level, id)