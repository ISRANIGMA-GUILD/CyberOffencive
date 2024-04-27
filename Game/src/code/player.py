import pygame
from entity import *
from settings import *
from utils import *
from inventory import *
from weapon import *


class Player(Entity):
    def __init__(self, position: tuple, groups, obstacle_sprites, create_attack, destroy_weapon,
                 path='../graphics/brawn_idle.png') -> None:
        self.max_stats: dict = {
            HEALTH: 100,
            ENERGY: 100,
            DAMAGE: 20,
            SPEED: 10.0,
        }

        self.min_stats: dict = {
            HEALTH: 0,
            ENERGY: 0,
            DAMAGE: 0,
            SPEED: 5.0,
        }

        self.stats: dict = {
            HEALTH: 85,  # 100,
            ENERGY: 40,
            DAMAGE: 10,
            SPEED: 5.0,
        }

        super().__init__(groups, self.stats[SPEED])
        self.image = pygame.image.load(path).convert_alpha()

        self.rect = self.image.get_rect(topleft=position)
        self.hitbox = self.rect.inflate(-18, -26)

        self.inventory = Inventory(4, 8)

        self.import_player_assets()
        self.status = DOWN

        self.frame_index = 0
        self.animation_speed = 0.15

        self.direction = pygame.math.Vector2()
        self.attacking = False

        self.attack_cooldown = 400
        self.attack_time = None

        self.using_item = False
        self.obstacle_sprites = obstacle_sprites

        self.create_attack = create_attack
        self.destroy_weapon = destroy_weapon

        self.can_switch_items = True
        self.item_switch_time = None

        self.switch_duration_cooldown = 200
        self.vulnerable = True

        self.hurt_time = None
        self.invulnerability_duration = 500

    def import_player_assets(self, path: str = '../graphics/player/') -> None:
        """

        :param path:
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
        }

        for animation in self.animations.keys():
            animation_path = path + animation
            self.animations[animation] = import_folder(animation_path)

    def input(self) -> None:
        """

        """

        keys = pygame.key.get_pressed()

        if not self.attacking and not self.using_item:
            if keys[pygame.K_UP] or keys[pygame.K_w]:
                self.direction.y = -1
                self.status = UP

            elif keys[pygame.K_DOWN] or keys[pygame.K_s]:
                self.direction.y = 1
                self.status = DOWN

            else:
                self.direction.y = 0

            if keys[pygame.K_LEFT] or keys[pygame.K_a]:
                self.direction.x = -1
                self.status = LEFT

            elif keys[pygame.K_RIGHT] or keys[pygame.K_d]:
                self.direction.x = 1
                self.status = RIGHT

            else:
                self.direction.x = 0

        # Attack with current item if it is weapon    
        if (keys[pygame.K_f] or pygame.mouse.get_pressed()[0]) and not self.attacking:
            if len(self.inventory.hotbar.content[self.inventory.hotbar.active_item_index]) >= 1 and issubclass(
                    self.inventory.hotbar.content[self.inventory.hotbar.active_item_index][0].__class__, Weapon):
                self.attacking = True
                self.attack_time = pygame.time.get_ticks()

                self.inventory.hotbar.content[self.inventory.hotbar.active_item_index][0].attack(self)
                # self.create_attack()

        elif (keys[pygame.K_f]) and not self.attacking:
            self.using_item = False
            self.attacking = True

            self.attack_time = pygame.time.get_ticks()
            print("Spells...")

            # Decrease hotbar active item index
        elif keys[pygame.K_q] and self.can_switch_items:
            self.can_switch_items = False
            self.item_switch_time = pygame.time.get_ticks()
            self.inventory.hotbar.decrease_active_item_index()

        # Increase hotbar active item index    
        elif keys[pygame.K_e] and self.can_switch_items:
            self.can_switch_items = False
            self.item_switch_time = pygame.time.get_ticks()
            self.inventory.hotbar.increase_active_item_index()

            # Use current active item
        elif keys[pygame.K_u] and not self.attacking:
            self.attacking = True
            self.using_item = True

            self.attack_time = pygame.time.get_ticks()
            self.inventory.hotbar.apply_active_item(self)

    def get_status(self) -> None:
        """

        """

        if not self.direction.x and not self.direction.y:
            if not IDLE in self.status and not ATTACK in self.status:
                self.status += IDLE

        if self.attacking:
            self.direction.x = 0
            self.direction.y = 0

            if not ATTACK in self.status:
                if IDLE in self.status:
                    self.status = self.status.replace(IDLE, ATTACK)

                else:
                    self.status += ATTACK

        else:
            self.status = self.status.replace(ATTACK, NO_ACTION)

    def cooldowns(self) -> None:
        """

        """

        current_time = pygame.time.get_ticks()

        if self.attacking:
            if (current_time - self.attack_time) >= self.attack_cooldown:
                self.attacking = False
                self.using_item = False
                self.destroy_weapon()

        if not self.can_switch_items:
            if (current_time - self.item_switch_time) >= self.switch_duration_cooldown:
                self.can_switch_items = True

        if not self.vulnerable:
            if (current_time - self.hurt_time) >= self.invulnerability_duration:
                self.vulnerable = True

    def animate(self) -> None:
        """

        """

        animation = self.animations[self.status]
        self.frame_index += self.animation_speed

        if self.frame_index >= len(animation):
            self.frame_index = 0

        self.image = animation[int(self.frame_index)]
        self.rect = self.image.get_rect(center=self.hitbox.center)

        if not self.vulnerable:
            alpha = self.wave_value()
            self.image.set_alpha(alpha)

        else:
            self.image.set_alpha(255)

    def update(self) -> None:
        """

        """

        self.input()
        self.cooldowns()

        self.get_status()
        self.animate()

        self.move()
        self.inventory.update()

    def get_location(self):
        """

        :return:
        """

        return self.rect.x, self.rect.y

    def get_status_frame_index(self):
        """

        :return:
        """

        return self.frame_index
