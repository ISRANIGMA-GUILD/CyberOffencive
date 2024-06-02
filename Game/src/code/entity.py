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

    def move(self, collision_grid):
        # ... other logic ...
        if self.collision_grid is None:
            self.collision_grid = collision_grid

        if self.direction.magnitude():
            self.direction = self.direction.normalize()

        # Calculate movement distances
        dx = self.direction.x * self.stats[SPEED]
        dy = self.direction.y * self.stats[SPEED]

        # Check for collisions separately for x and y axes
        if dx != 0:
            self.hitbox.x += dx
            if self.collision(HORIZONTAL, collision_grid):
                self.hitbox.x -= dx

        if dy != 0:
            self.hitbox.y += dy
            if self.collision(VERTICAL, collision_grid):
                self.hitbox.y -= dy

        self.rect.center = self.hitbox.center

    def collision(self, direction: str, collision_grid) -> bool:
        collision_occurred = False
        entity_x, entity_y = collision_grid.get_grid_coords(self.hitbox.centerx, self.hitbox.centery)
        for grid_x in range(entity_x - 1, entity_x + 2):
            for grid_y in range(entity_y - 1, entity_y + 2):
                for obstacle in collision_grid.grid[grid_x][grid_y]:
                    if self.hitbox.colliderect(obstacle.hitbox):
                        if HORIZONTAL == direction:
                            # Movement to the right side
                            if self.direction.x > 0:
                                self.hitbox.right = obstacle.hitbox.left
                            # Movement to the left side
                            if self.direction.x < 0:
                                self.hitbox.left = obstacle.hitbox.right
                        elif VERTICAL == direction:
                            # Movement down
                            if self.direction.y > 0:
                                self.hitbox.bottom = obstacle.hitbox.top
                            # Movement up
                            if self.direction.y < 0:
                                self.hitbox.top = obstacle.hitbox.bottom
                        collision_occurred = True
                        break
                if collision_occurred:
                    break
        return collision_occurred

    def wave_value(self) -> float:
        value = sin(pygame.time.get_ticks())
        return 255 if value >= 0 else 0
