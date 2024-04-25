import pygame
from settings import *
from math import sin


class Entity(pygame.sprite.Sprite):
    def __init__(self, groups, speed: float):
        super().__init__(groups)
        self.frame_index = 0

        self.animation_speed = 0.15
        self.direction = pygame.math.Vector2()
        self.speed = speed

    def move(self) -> None:
        """

        """

        if self.direction.magnitude():
            self.direction = self.direction.normalize()

        self.hitbox.x += self.direction.x * self.speed
        self.collision(HORIZONTAL)

        self.hitbox.y += self.direction.y * self.speed
        self.collision(VERTICAL)
        self.rect.center = self.hitbox.center

    def collision(self, direction: str) -> None:
        """

        :param direction:
        """

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

    def wave_value(self) -> float:
        """

        :return:
        """

        value = sin(pygame.time.get_ticks())
        return 255 if value >= 0 else 0
