import pygame
from settings import *


class YSortCameraGroup(pygame.sprite.Group):
    def __init__(self, custom_empty_timeout: int = 0) -> None:
        super().__init__()
        self.display_surface = pygame.display.get_surface()

        self.half_width = self.display_surface.get_size()[0] // 2
        self.half_height = self.display_surface.get_size()[1] // 2
        self.offset = pygame.math.Vector2()
        
        self.custom_empty_timeout = custom_empty_timeout
        self.current_time = None
        self.empty_time = None
        self.can_empty = True

    def custom_draw(self, player):
        self.offset.x = player.rect.centerx - self.half_width
        self.offset.y = player.rect.centery - self.half_height

        # Only draw the other sprites, not the tilemap
        for sprite in sorted(self.sprites(), key=lambda sprite: sprite.rect.centery):
            offset_position = sprite.rect.topleft - self.offset
            self.display_surface.blit(sprite.image, offset_position)

    def enemy_update(self, player, projectiles_group) -> None:
        enemy_sprites = [sprite for sprite in self.sprites() if
                         hasattr(sprite, 'sprite_type') and (ENEMY == sprite.sprite_type)]
        for enemy in enemy_sprites:
            if FRENZY == enemy.monster_name:
                enemy.enemy_update(player, projectiles_group)
            else:
                enemy.enemy_update(player)
    
    
    def custom_empty(self) -> None:
        if self.can_empty:
            self.empty_time = pygame.time.get_ticks()
            self.empty()
            self.can_empty = False
        else:
            self.current_time = pygame.time.get_ticks()
            if (self.current_time - self.empty_time) >= self.custom_empty_timeout:
                self.can_empty = True