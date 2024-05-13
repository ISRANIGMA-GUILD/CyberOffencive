import pygame
from settings import *
import math

class Arrow(pygame.sprite.Sprite):
    def __init__(self, angle, position: tuple, groups, damage: int) -> None:
        super().__init__(groups)
        
        self.angle = angle
        self.velocity = pygame.math.Vector2(0, 0)
        self.set_velocity(self.angle)

        self.sprite_type = WEAPON

        self.life_time = 300

        self.damage = damage

        self.image = pygame.transform.scale(pygame.image.load('../graphics/weapons/bow/arrow.png').convert_alpha(), (30, 10))
        self.image = pygame.transform.rotate(self.image, self.angle)
        self.rect = self.image.get_rect(topleft=position)
    
    
    def move(self) -> None:
        self.rect.x += self.velocity.x
        self.rect.y += self.velocity.y


    def set_velocity(self, angle) -> None:
        # Assuming angle is in degrees
        angle_radians = math.radians(angle)
        
        # Define the magnitude of the velocity (speed of the arrow)
        arrow_speed = 7 # Adjust this value as needed

        # Calculate the horizontal and vertical components of velocity using trigonometry
        self.velocity.x = arrow_speed * math.cos(angle_radians)
        self.velocity.y = -arrow_speed * math.sin(angle_radians)  # Negative because y increases downwards in pygame


    def update(self) -> None:
        self.move()
        self.life_time -= 1
        if self.life_time <= 0:
            self.kill()