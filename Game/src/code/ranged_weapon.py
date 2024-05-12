import pygame
from weapon import *
from settings import *
import math
from arrow import Arrow

class RangedWeapon(Weapon):
    def __init__(self, position, groups, groups_for_arrow, cooldown: int, damage: int, weapon_name: str) -> None:
        super().__init__(position, groups, cooldown, damage, weapon_name)
        self.image_paths[ON_MAP] = f'../graphics/weapons/{weapon_name}/on_map.png'
        self.image_paths[ON_HOTBAR] = f'../graphics/weapons/{weapon_name}/on_hotbar.png'
        self.damage = damage
        self.groups_for_arrow = groups_for_arrow
        self.stats: dict = {
            DAMAGE: 0,
            COOLDOWN: cooldown,
        }

    # TODO: when we finish graphics scale the weapons in the graphics and delete the pygame scaling
    def attack(self, player) -> None:
        self.direction = player.status.split(UNDERSCORE, 1)[0]
        self.full_path = f'../graphics/weapons/{self.weapon_name}/{self.direction}.png' 
        if self.direction in [DOWN, UP]:
            self.image = pygame.transform.scale(pygame.image.load(self.full_path).convert_alpha(), (60, 40))
        elif self.direction in [LEFT, RIGHT]:
            self.image = pygame.transform.scale(pygame.image.load(self.full_path).convert_alpha(), (40, 60))

        self.rect = self.image.get_rect(center = player.rect.center)

        if RIGHT == self.direction:
            self.rect = self.image.get_rect(midleft = player.rect.midright + pygame.math.Vector2(-10, 3)) # 0, 16
        elif LEFT == self.direction:
            self.rect = self.image.get_rect(midright = player.rect.midleft + pygame.math.Vector2(10, -3)) # 0, 16
        elif DOWN == self.direction:
            self.rect = self.image.get_rect(midtop = player.rect.midbottom + pygame.math.Vector2(-6, -16)) # -10, 0
        elif UP == self.direction:
            self.rect = self.image.get_rect(midbottom = player.rect.midtop + pygame.math.Vector2(10, 10)) # -10, 0
        
        
        if self.can_shoot():
            self.create_arrow(player, self.groups_for_arrow, self.damage)


    def create_arrow(self, player, groups, arrow_damage) -> None:
        angle = self.get_angle()
        Arrow(angle, self.rect.center, groups, arrow_damage)
        

    def get_angle(self) -> None:
        mouse_position = pygame.mouse.get_pos()
        adjusted_mouse_position = pygame.Vector2(mouse_position[0] - (HALF_WIDTH - 50), mouse_position[1] - (HALF_HEIGHT - 50))
        angle = math.atan2(-adjusted_mouse_position.y, adjusted_mouse_position.x)  # atan2 gives you the angle to the target.
        angle %= math.tau
        angle = math.degrees(angle)
        return angle
    
    
    def can_shoot(self) -> bool:
        mx, my = pygame.mouse.get_pos()
        
        if (UP == self.direction) and (0 <= my <= HALF_HEIGHT - 50):
            return True
        elif (LEFT == self.direction) and (0 <= mx <= HALF_WIDTH - 50):
            return True
        elif (DOWN == self.direction) and (HALF_HEIGHT - 50 <= my <= HEIGHT):
            return True
        elif (RIGHT == self.direction) and (HALF_WIDTH - 50 <= mx <= WIDTH):
            return True
        return False