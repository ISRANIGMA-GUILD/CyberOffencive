import pygame
from settings import *
from math import sin


class Entity(pygame.sprite.Sprite):
    def __init__(self, groups):
        self.stats = self.stats
        super().__init__(groups)
        self.frame_index = 0
        self.animation_speed = 0.15
        self.direction = pygame.math.Vector2()
        self.collision_grid = None

    def move(self, collision_grid) -> None:
        #return
        if self.collision_grid is None:
            self.collision_grid = collision_grid

        if self.direction.magnitude():
            self.direction = self.direction.normalize()


        # Then check for collisions 
        entity_x, entity_y = self.collision_grid.get_grid_coords(self.hitbox.centerx, self.hitbox.centery)
        for grid_x in range(entity_x - 1, entity_x + 2):
            for grid_y in range(entity_y - 1, entity_y + 2):
                for obstacle in self.collision_grid.grid[grid_x][grid_y]:
                    self.collision(HORIZONTAL, obstacle)
                    self.collision(VERTICAL, obstacle)

        self.hitbox.x += self.direction.x * self.stats[SPEED]
        self.hitbox.y += self.direction.y * self.stats[SPEED]
        self.rect.center = self.hitbox.center

    def collision(self, direction: str, sprite) -> None:
        if HORIZONTAL == direction:
            if sprite.hitbox.colliderect(self.hitbox):
                # Movement to the right side
                if self.direction.x > 0:
                    self.hitbox.right = sprite.hitbox.left
                # Movement to the left side
                if self.direction.x < 0:
                    self.hitbox.left = sprite.hitbox.right

        elif VERTICAL == direction:
            for sprite in self.obstacle_sprites:
                if sprite.hitbox.colliderect(self.hitbox):
                    # Movement down
                    if self.direction.y > 0:
                        self.hitbox.bottom = sprite.hitbox.top
                    # Movement up
                    if self.direction.y < 0:
                        self.hitbox.top = sprite.hitbox.bottom

    def wave_value(self) -> float:
        value = sin(pygame.time.get_ticks())
        return 255 if value >= 0 else 0
