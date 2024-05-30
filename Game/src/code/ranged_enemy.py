import pygame
from enemy import Enemy
from settings import *
from laser_beam import LaserBeam
import math


class RangedEnemy(Enemy):
    def __init__(self, monster_name: str, position: tuple, groups, obstacle_sprites, damage_player_func, attack_type,
                 level) -> None:
        super().__init__(monster_name, position, groups, obstacle_sprites, damage_player_func, attack_type, level)

    def get_status(self, player) -> None:
        distance, self.direction = self.get_player_distance_and_direction(player)

        # if DEATH in self.status:
        #   print("status, if the player died what am i doing?", self.status, player.rect.center, distance, )
        if 'death' == self.status:
            return

        if not ATTACK in self.status:
            if self.direction.x <= -0.9:
                self.status = LEFT

            elif self.direction.x >= 0.9:
                self.status = RIGHT

            else:
                if self.direction.y < 0:
                    self.status = UP

                elif self.direction.y > 0:
                    self.status = DOWN

        if not self.direction.x and not self.direction.y:
            if not IDLE in self.status and not ATTACK in self.status:
                self.status += IDLE

        if distance <= self.stats[ATTACK_RADIUS]:
            if not ATTACK in self.status:
                if IDLE in self.status:
                    self.status = self.status.replace(IDLE, ATTACK)

                else:
                    self.status += ATTACK

                self.frame_index = 0
        elif distance <= self.stats[NOTICE_RADIUS]:
            self.status = self.status.replace(ATTACK, NO_ACTION)
            self.status = self.status.replace(IDLE, NO_ACTION)

        else:
            if not ATTACK in self.status:
                self.status += IDLE

    def actions(self, player, groups_for_projectile) -> None:
        distance, self.direction = self.get_player_distance_and_direction(player)
        if distance <= self.stats[ATTACK_RADIUS] and self.can_attack and ATTACK in self.status:
            self.attack_time = pygame.time.get_ticks()
            self.can_attack = False
            if player.stats[HEALTH] > 0:
                if DOWN in self.status:
                    LaserBeam(math.degrees(1.5 * math.pi), self.hitbox.center, groups_for_projectile, 5)
                elif UP in self.status:
                    LaserBeam(math.degrees(0.5 * math.pi), self.hitbox.center, groups_for_projectile, 5)
                elif LEFT in self.status:
                    LaserBeam(math.degrees(math.pi), self.hitbox.center, groups_for_projectile, 5)
                else:
                    LaserBeam(0, self.hitbox.center, groups_for_projectile, 5)

        elif self.status in [UP, DOWN, LEFT, RIGHT]:
            _, self.direction = self.get_player_distance_and_direction(player)

        else:
            self.direction = pygame.math.Vector2(0, 0)

    def enemy_update(self, player, groups_for_projectile) -> None:
        self.get_status(player)
        self.actions(player, groups_for_projectile)
