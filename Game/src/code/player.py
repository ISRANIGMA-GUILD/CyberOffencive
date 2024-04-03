import pygame
from entity import *
from settings import *


class Player(pygame.sprite.Sprite):
    def __init__(self, position: tuple, groups, obstacle_sprites, path = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\Graphics\\brawn_idle.png') -> None:
        super().__init__(groups)
        self.image = pygame.image.load(path).convert_alpha()
        self.rect = self.image.get_rect(topleft=position)
        self.direction = pygame.math.Vector2()
        self.hitbox = self.rect.inflate(-18, -26)
                
        self.obstacle_sprites = obstacle_sprites
         
    def input(self) -> None:
        keys = pygame.key.get_pressed()
        
        if keys[pygame.K_UP] or keys[pygame.K_w]:
            self.direction.y = -1
        elif keys[pygame.K_DOWN] or keys[pygame.K_s]:
            self.direction.y = 1
        else:
            self.direction.y = 0
        
        if keys[pygame.K_LEFT] or keys[pygame.K_a]:
            self.direction.x = -1
        elif keys[pygame.K_RIGHT] or keys[pygame.K_d]:
            self.direction.x = 1
        else:
            self.direction.x = 0

    def move(self, speed: float) -> None:
        if self.direction.magnitude():
            self.direction = self.direction.normalize()
        
        self.hitbox.x += self.direction.x * speed
        self.collision(HORIZONTAL)
        self.hitbox.y += self.direction.y * speed
        self.collision(VERTICAL)    
        self.rect.center = self.hitbox.center    

    def collision(self, direction) -> None:
        if HORIZONTAL == direction:
            for obstacle in self.obstacle_sprites:
                if self != obstacle and obstacle.hitbox.colliderect(self.hitbox):
                    if self.direction.x > 0:
                        self.hitbox.right = obstacle.hitbox.left
                    if self.direction.x < 0:
                        self.hitbox.left = obstacle.hitbox.right                    
                            
        elif VERTICAL == direction:
            for obstacle in self.obstacle_sprites:
                if self != obstacle and obstacle.hitbox.colliderect(self.hitbox):
                    if self.direction.y > 0:
                        self.hitbox.bottom = obstacle.hitbox.top
                    if self.direction.y < 0:
                        self.hitbox.top = obstacle.hitbox.bottom   

    def update(self) -> None:
        self.input()
        self.move(5.0)

    def get_location(self):
        """

        :return:
        """

        return f"L {self.rect.x} {self.rect.y}"
