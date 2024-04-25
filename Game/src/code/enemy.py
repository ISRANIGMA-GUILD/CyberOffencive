import pygame
from settings import *
from entity import *
from utils import *
from hp_fruit import *
from energy_fruit import *
from random import randint


class Enemy(Entity):
    def __init__(self, monster_name: str, position: tuple, groups, obstacle_sprites, damage_player_func, attack_type,
                 level) -> None:
        self.stats = {
            HEALTH: ENEMIES_DATA[monster_name][HEALTH],
            SPEED: ENEMIES_DATA[monster_name][SPEED],
            DAMAGE: ENEMIES_DATA[monster_name][DAMAGE],
            RESISTANCE: ENEMIES_DATA[monster_name][RESISTANCE],
		    ATTACK_RADIUS: ENEMIES_DATA[monster_name][ATTACK_RADIUS],
		    NOTICE_RADIUS: ENEMIES_DATA[monster_name][NOTICE_RADIUS],
        }
        
        self.level = level
        
        super().__init__(groups, self.stats[SPEED])
        
        self.sprite_type = ENEMY
        self.monster_name = monster_name

        self.import_graphics()
        self.status = 'up_idle'
        
        self.image = self.animations[self.status][self.frame_index]
        self.rect = self.image.get_rect(topleft = position)

        self.hitbox = self.rect.inflate(-10, -20)
        self.obstacle_sprites = obstacle_sprites
        
        self.can_attack = True
        self.attack_time = None

        self.attack_cooldown = 400
        self.vulnerable = True

        self.hit_time = None
        self.invincibility_duration = 400
        
        self.damage_player = damage_player_func
        self.attack_type = attack_type

    def import_graphics(self) -> None:
        """

        """

        self.animations = {
            'up': [],
            'down': [],
            'left': [],
            'right': [],
            'up_idle': [],
            'down_idle': [],
            'left_idle': [],
            'right_idle': [],
            'up_attack': [],
            'down_attack': [],
            'left_attack': [],
            'right_attack': [],
            'death': [],
        }

        base_path = f'../graphics/enemies/{self.monster_name}/'
        
        for animation in self.animations.keys():
            self.animations[animation] = import_folder(base_path + animation)

    def get_player_distance_and_direction(self, player) -> tuple:
        """

        :param player:
        :return:
        """

        enemy_vector = pygame.math.Vector2(self.rect.center)
        player_vector = pygame.math.Vector2(player.rect.center)
        distance = (player_vector - enemy_vector).magnitude()
        
        if distance > 0:
            direction = (player_vector - enemy_vector).normalize()

        else:
            direction = pygame.math.Vector2(0, 0)    
        
        return (distance, direction)
    
    def get_status(self, player) -> None:
        """

        :param player:
        :return:
        """

        distance, self.direction = self.get_player_distance_and_direction(player)

        #if DEATH in self.status:
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
                  
        if distance <= self.stats[ATTACK_RADIUS] and self.can_attack:
            self.direction.x = 0
            self.direction.y = 0

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
            self.status += IDLE

    def actions(self, player) -> None:
        """

        :param player:
        """

        if ATTACK in self.status:
            self.attack_time = pygame.time.get_ticks()
            self.damage_player(player, self.stats[DAMAGE], self.attack_type)

        elif self.status in [UP, DOWN, LEFT, RIGHT]:
            _, self.direction = self.get_player_distance_and_direction(player)

        else:
            self.direction = pygame.math.Vector2(0,0)

    def animate(self) -> None:
        """

        """

        animation = self.animations[self.status]
        self.frame_index += self.animation_speed

        if self.frame_index >= len(animation):
            if ATTACK in self.status:
                self.can_attack = False

            elif 'death' == self.status:
                HPFruit(self.hitbox.center, [self.level.visible_sprites])
                EnergyFruit(self.hitbox.center + pygame.math.Vector2(20, 20), [self.level.visible_sprites])
                
                self.status = 'up_idle'
                self.hitbox.center = (randint(900, 2000), randint(900, 3000))

                self.frame_index = 0
                self.stats[HEALTH] = ENEMIES_DATA[self.monster_name][HEALTH]
                
            self.frame_index = 0
        
        self.image = animation[int(self.frame_index)]
        self.rect = self.image.get_rect(center = self.hitbox.center)
        
        if not self.vulnerable:
            alpha = self.wave_value()
            self.image.set_alpha(alpha)

        else:
            self.image.set_alpha(255)    

    def cooldowns(self) -> None:
        """

        """

        current_time = pygame.time.get_ticks()
        
        if not self.can_attack:
            if (current_time - self.attack_time) >= self.attack_cooldown:
                self.can_attack = True
        
        if not self.vulnerable:
            if (current_time - self.hit_time) >= self.invincibility_duration:
                self.vulnerable = True

    def get_damage(self, player, attack_type) -> None:
        """

        :param player:
        :param attack_type:
        :return:
        """

        if not self.vulnerable:
            return

        _, self.direction = self.get_player_distance_and_direction(player)

        if WEAPON == attack_type:
            self.stats[HEALTH] -= player.inventory.hotbar.content[player.inventory.hotbar.active_item_index][0].stats[DAMAGE]

        else:
            # skills and so on
            pass

        self.hit_time = pygame.time.get_ticks() 
        self.vulnerable = False

    def check_death(self) -> None:
        """

        """

        if self.stats[HEALTH] <= 0:
            self.status = 'death'

    def hit_reaction(self) -> None:
        """

        """

        if not self.vulnerable:
            self.direction *= -self.stats[RESISTANCE]

    def update(self) -> None:
        """

        """

        self.hit_reaction()
        self.move()

        self.animate()
        self.cooldowns()
        self.check_death()

    def enemy_update(self, player) -> None:
        """

        :param player:
        """

        self.get_status(player)
        self.actions(player)