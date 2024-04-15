import pygame
from settings import *


class Entity(pygame.sprite.Sprite):
    def __init__(self, groups):
        super().__init__(groups)
        self.frame_index = 0
        self.animation_speed = 0.15
        self.direction = pygame.math.Vector2()
        
    def move(self, speed: float) -> None:
        if self.direction.magnitude():
            self.direction = self.direction.normalize()
        
        self.hitbox.x += self.direction.x * speed
        self.collision(HORIZONTAL)
        self.hitbox.y += self.direction.y * speed
        self.collision(VERTICAL)
        self.rect.center = self.hitbox.center
        
    def collision(self, direction: str) -> None:
        if HORIZONTAL == direction:
            for sprite in self.obstacle_sprites:
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
