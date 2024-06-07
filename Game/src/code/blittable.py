import pygame
from settings import *
import math

class Blittable(pygame.sprite.Sprite):
    def __init__(self, position: tuple, groups, path: str, width: int, height: int, is_projectile: bool = False, angle: float = 0.0) -> None:
        self.rect = pygame.Rect(0,0,0,0)
        super().__init__(groups)

        size = (width, height)
        if 'left' in path or 'right' in path:
            size = (height, width)

        player_rect = pygame.Rect(position, (57, 77))

        self.image = pygame.image.load(path).convert_alpha()
        
        self.angle = angle
        
        if is_projectile:
            self.image = pygame.transform.scale(self.image, (width, height))
            self.image = pygame.transform.rotate(self.image, self.angle)
            self.rect = self.image.get_rect(topleft=player_rect.center)
        else:
            self.image = pygame.transform.scale(self.image, size)
            
        if 'right' in path:
            self.rect = self.image.get_rect(midleft = player_rect.midright + pygame.math.Vector2(-10, 3)) # 0, 16
        elif 'left' in path:
            self.rect = self.image.get_rect(midright = player_rect.midleft + pygame.math.Vector2(10, -3)) # 0, 16
        elif 'down' in path:
            self.rect = self.image.get_rect(midtop = player_rect.midbottom + pygame.math.Vector2(-6, -16)) # -10, 0
        elif 'up' in path:
            self.rect = self.image.get_rect(midbottom = player_rect.midtop + pygame.math.Vector2(10, 10)) # -10, 0
    
        
        self.custom_velocity = pygame.math.Vector2(0, 0)
        self.set_custom_velocity()
    
    
    def set_custom_velocity(self) -> None:
        # Assuming angle is in degrees
        angle_radians = math.radians(self.angle)
        
        # Define the magnitude of the velocity (speed of the arrow)
        projectile_speed = 7 # Adjust this value as needed

        # Calculate the horizontal and vertical components of velocity using trigonometry
        self.custom_velocity.x = projectile_speed * math.cos(angle_radians)
        self.custom_velocity.y = -projectile_speed * math.sin(angle_radians)  # Negative because y increases downwards in pygame
        

    def custom_move(self) -> None:
        self.rect.x += self.custom_velocity.x
        self.rect.y += self.custom_velocity.y