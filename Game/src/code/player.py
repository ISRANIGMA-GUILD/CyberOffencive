from inventory import *
from enemy import *


class Player(Entity):
    def __init__(self, position: tuple, groups, enemies_group, obstacle_sprites, create_attack, destroy_weapon,
                 path=f'{BASE_PATH}/graphics/brawn_idle.png') -> None:
        self.max_stats: dict = {
            HEALTH: 100,
            ENERGY: 100,
            DAMAGE: 20,
            SPEED: 10.0,
        }

        self.min_stats: dict = {
            HEALTH: 0,
            ENERGY: 0,
            DAMAGE: 10,
            SPEED: 5.0,
        }

        self.stats: dict = {
            HEALTH: 85,  # 100,
            ENERGY: 60,
            DAMAGE: 10,
            SPEED: 5.0,
        }

        self.skills = {
            ATTACK_BOOST_SKILL_INDEX: {
                SKILL_ENERGY_COST: 50,
                SKILL_ICON_PATH: f'{BASE_PATH}/graphics/skills/attack_boost.png',
                SKILL_APPLY_FUNC: self.apply_attack_boost_skill,
                SKILL_COOLDOWN_DURATION: 60000,
                SKILL_ACTIVE_DURATION: 5000,
                SKILL_APPLY_TIME: None,
                SKILL_APPLIED: False,
                SKILL_ACTIVE: False,
            },

            SPEED_BOOST_SKILL_INDEX: {
                SKILL_ENERGY_COST: 50,
                SKILL_ICON_PATH: f'{BASE_PATH}/graphics/skills/speed_boost.png',
                SKILL_APPLY_FUNC: self.apply_speed_boost_skill,
                SKILL_COOLDOWN_DURATION: 60000,
                SKILL_ACTIVE_DURATION: 5000,
                SKILL_APPLY_TIME: None,
                SKILL_APPLIED: False,
                SKILL_ACTIVE: False,
            },

            REGENERATION_SKILL_INDEX: {
                SKILL_ENERGY_COST: 80,
                SKILL_ICON_PATH: f'{BASE_PATH}/graphics/skills/regeneration.png',
                SKILL_APPLY_FUNC: self.apply_regeneration_skill,
                SKILL_COOLDOWN_DURATION: 60000,
                SKILL_ACTIVE_DURATION: 2000,
                SKILL_APPLY_TIME: None,
                SKILL_APPLIED: False,
                SKILL_ACTIVE: False,
            }
        }

        super().__init__(groups)
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

        self.auto_play = False
        self.b_key_pressed = False
        self.enemies_group = enemies_group

    def import_player_assets(self, path: str = f'{BASE_PATH}/graphics/player/') -> None:
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
        keys = pygame.key.get_pressed()

        if keys[pygame.K_b] and not self.b_key_pressed:
            self.auto_play = not self.auto_play
            self.b_key_pressed = True
            self.switch_to_weapon()  # Automatically switch to weapon when 'b' is pressed
        elif not keys[pygame.K_b]:
            self.b_key_pressed = False

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

        elif (keys[pygame.K_m]) and not self.attacking:
            self.using_item = False
            self.attacking = True
            self.attack_time = pygame.time.get_ticks()
            # print("Spells...")

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

        if keys[pygame.K_1] and not self.skills[ATTACK_BOOST_SKILL_INDEX][SKILL_APPLIED]:
            self.skills[ATTACK_BOOST_SKILL_INDEX][SKILL_APPLY_FUNC]()


        elif keys[pygame.K_2] and not self.skills[SPEED_BOOST_SKILL_INDEX][SKILL_APPLIED]:
            self.skills[SPEED_BOOST_SKILL_INDEX][SKILL_APPLY_FUNC]()


        elif keys[pygame.K_3] and not self.skills[REGENERATION_SKILL_INDEX][SKILL_APPLIED]:
            self.skills[REGENERATION_SKILL_INDEX][SKILL_APPLY_FUNC]()

    def switch_to_weapon(self) -> None:
        for i, item_list in enumerate(self.inventory.hotbar.content):
            if item_list and issubclass(item_list[0].__class__, Weapon):
                self.inventory.hotbar.active_item_index = i
                break

    def get_status(self) -> None:
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

        for skill_index in self.skills.keys():
            if self.skills[skill_index][SKILL_APPLIED]:
                delta_time = (current_time - self.skills[skill_index][SKILL_APPLY_TIME])
                if self.skills[skill_index][SKILL_ACTIVE]:
                    if delta_time >= self.skills[skill_index][SKILL_ACTIVE_DURATION]:
                        self.skills[skill_index][SKILL_ACTIVE] = False
                        if SPEED_BOOST_SKILL_INDEX == skill_index:
                            self.stats[SPEED] = self.min_stats[SPEED]
                    else:
                        if REGENERATION_SKILL_INDEX == skill_index:
                            self.stats[HEALTH] += 1
                            if self.stats[HEALTH] > self.max_stats[HEALTH]:
                                self.stats[HEALTH] = self.max_stats[HEALTH]
                else:
                    if delta_time >= self.skills[skill_index][SKILL_COOLDOWN_DURATION] + self.skills[skill_index][
                        SKILL_ACTIVE_DURATION]:
                        self.skills[skill_index][SKILL_APPLIED] = False

    def animate(self) -> None:
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

    def render_skills(self) -> None:
        display_surface = pygame.display.get_surface()

        for skill_index in self.skills:
            skill_image = pygame.image.load(self.skills[skill_index][SKILL_ICON_PATH]).convert_alpha()
            skill_rect = pygame.Rect(500 + 30 + (skill_index - DEC) * 50 + (skill_index - DEC) * 20, 470, 50, 50)

            display_surface.blit(skill_image, skill_rect)

            if self.skills[skill_index][SKILL_APPLIED]:
                if self.skills[skill_index][SKILL_ACTIVE]:
                    pygame.draw.rect(display_surface, SKILLS_ACTIVE_OUTLINE_COLOR, skill_rect,
                                     border_radius=SKILLS_BORDER_RADIUS, width=SKILLS_ACTIVE_OUTLINE_WIDTH)
                else:
                    pygame.draw.rect(display_surface, SKILLS_COOLDOWN_OUTLINE_COLOR, skill_rect,
                                     border_radius=SKILLS_BORDER_RADIUS, width=SKILLS_COOLDOWN_OUTLINE_WIDTH)
            pygame.draw.rect(display_surface, SKILLS_OUTLINE_COLOR, skill_rect, border_radius=SKILLS_BORDER_RADIUS,
                             width=SKILLS_OUTLINE_WIDTH)

    def apply_attack_boost_skill(self) -> None:
        if self.stats[ENERGY] - self.skills[ATTACK_BOOST_SKILL_INDEX][SKILL_ENERGY_COST] < 0:
            return

        self.skills[ATTACK_BOOST_SKILL_INDEX][SKILL_APPLIED] = True
        self.skills[ATTACK_BOOST_SKILL_INDEX][SKILL_APPLY_TIME] = pygame.time.get_ticks()
        self.skills[ATTACK_BOOST_SKILL_INDEX][SKILL_ACTIVE] = True
        self.stats[ENERGY] -= self.skills[ATTACK_BOOST_SKILL_INDEX][SKILL_ENERGY_COST]

    def apply_speed_boost_skill(self) -> None:
        if self.stats[ENERGY] - self.skills[SPEED_BOOST_SKILL_INDEX][SKILL_ENERGY_COST] < 0:
            return

        self.skills[SPEED_BOOST_SKILL_INDEX][SKILL_APPLIED] = True
        self.skills[SPEED_BOOST_SKILL_INDEX][SKILL_APPLY_TIME] = pygame.time.get_ticks()
        self.skills[SPEED_BOOST_SKILL_INDEX][SKILL_ACTIVE] = True
        self.stats[ENERGY] -= self.skills[SPEED_BOOST_SKILL_INDEX][SKILL_ENERGY_COST]
        self.stats[SPEED] = self.max_stats[SPEED]

    def apply_regeneration_skill(self) -> None:
        if self.stats[ENERGY] - self.skills[REGENERATION_SKILL_INDEX][SKILL_ENERGY_COST] < 0:
            return

        self.skills[REGENERATION_SKILL_INDEX][SKILL_APPLIED] = True
        self.skills[REGENERATION_SKILL_INDEX][SKILL_APPLY_TIME] = pygame.time.get_ticks()
        self.skills[REGENERATION_SKILL_INDEX][SKILL_ACTIVE] = True
        self.stats[ENERGY] -= self.skills[REGENERATION_SKILL_INDEX][SKILL_ENERGY_COST]

    def apply_magnet_skill(self) -> None:
        pass

    def auto_play_movement(self) -> None:
        keys = pygame.key.get_pressed()
        if keys[pygame.K_b] and not self.b_key_pressed:
            self.auto_play = not self.auto_play
            self.b_key_pressed = True
        elif not keys[pygame.K_b]:
            self.b_key_pressed = False

        closest_enemy = None
        for enemy in self.enemies_group:
            smallest_distance = 1000000
            closest_enemy = None
            for enemy in self.enemies_group:
                distance = self.distance_to(enemy)
                if distance < smallest_distance:
                    smallest_distance = distance
                    closest_enemy = enemy

        if closest_enemy:
            self.direction, _ = self.get_player_distance_and_direction(closest_enemy)
            self.status = self.get_status_from_direction(self.direction)

            if smallest_distance < ATTACK_DISTANCE and self.inventory.has_weapon():
                self.attack_enemy(closest_enemy)

        else:
            self.direction = pygame.math.Vector2(0, 0)

        if self.direction.x == 0 and self.direction.y == 0 and not IDLE in self.status:
            self.status = self.status.replace(ATTACK, NO_ACTION)
            self.status += IDLE

    def attack_enemy(self, enemy) -> None:
        if not self.attacking:
            self.attacking = True
            self.attack_time = pygame.time.get_ticks()
            self.inventory.hotbar.content[self.inventory.hotbar.active_item_index][0].attack(self)

    def get_status_from_direction(self, direction: pygame.math.Vector2) -> str:
        if direction.x < 0:
            return LEFT

        elif direction.x > 0:
            return RIGHT

        else:

            if direction.y < 0:

                return UP
            elif direction.y > 0:

                return DOWN

        return self.status

    def get_player_distance_and_direction(self, player) -> tuple:

        enemy_vector = pygame.math.Vector2(self.rect.center)
        player_vector = pygame.math.Vector2(player.rect.center)

        distance = (player_vector - enemy_vector).magnitude()

        if distance > 0:
            direction = (player_vector - enemy_vector)
            if direction.x < 0:
                direction.x = -1

            elif direction.x > 0:
                direction.x = 1

            if direction.y < 0:
                direction.y = -1

            elif direction.y > 0:
                direction.y = 1

        else:
            direction = pygame.math.Vector2(0, 0)

        return (direction, distance)

    def distance_to(self, entity) -> float:

        player_vector = pygame.math.Vector2(self.hitbox.center)
        entity_vector = pygame.math.Vector2(entity.hitbox.center)

        return (entity_vector - player_vector).magnitude()

    def am_i_dead(self) -> None:

        if self.stats[HEALTH] <= 0:
            # print(self.status)
            self.position = (2500, 1500)

            self.rect = self.image.get_rect(topleft=self.position)
            self.hitbox = self.rect.inflate(-18, -26)

            self.init_player()
            # print("You are dead!!!")

    def init_player(self) -> None:

        self.status = DOWN
        self.frame_index = 0

        self.animation_speed = 0.15
        self.stats = {HEALTH: 85, ENERGY: 60, DAMAGE: 10, SPEED: 5.0}

        self.direction = pygame.math.Vector2(0, 0)
        self.attacking = False

        self.attack_cooldown = 400
        self.attack_time = None

        self.using_item = False
        self.can_switch_items = True

        self.item_switch_time = None
        self.switch_duration_cooldown = 200

        self.vulnerable = False
        self.hurt_time = pygame.time.get_ticks()
        self.invulnerability_duration = 500

        self.skills = {
            ATTACK_BOOST_SKILL_INDEX: {
                SKILL_ENERGY_COST: 50,
                SKILL_ICON_PATH: f'{BASE_PATH}/graphics/skills/attack_boost.png',
                SKILL_APPLY_FUNC: self.apply_attack_boost_skill,
                SKILL_COOLDOWN_DURATION: 60000,
                SKILL_ACTIVE_DURATION: 5000,
                SKILL_APPLY_TIME: None,
                SKILL_APPLIED: False,
                SKILL_ACTIVE: False,
            },

            SPEED_BOOST_SKILL_INDEX: {
                SKILL_ENERGY_COST: 50,
                SKILL_ICON_PATH: f'{BASE_PATH}/graphics/skills/speed_boost.png',
                SKILL_APPLY_FUNC: self.apply_speed_boost_skill,
                SKILL_COOLDOWN_DURATION: 60000,
                SKILL_ACTIVE_DURATION: 5000,
                SKILL_APPLY_TIME: None,
                SKILL_APPLIED: False,
                SKILL_ACTIVE: False,
            },

            REGENERATION_SKILL_INDEX: {
                SKILL_ENERGY_COST: 80,
                SKILL_ICON_PATH: f'{BASE_PATH}/graphics/skills/regeneration.png',
                SKILL_APPLY_FUNC: self.apply_regeneration_skill,
                SKILL_COOLDOWN_DURATION: 60000,
                SKILL_ACTIVE_DURATION: 2000,
                SKILL_APPLY_TIME: None,
                SKILL_APPLIED: False,
                SKILL_ACTIVE: False,
            }
        }

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

    def update(self, collision_grid) -> None:

        if not self.auto_play:
            self.input()
            self.cooldowns()

            self.get_status()
            self.animate()

            self.move(collision_grid)
            self.inventory.update()

        else:
            self.auto_play_movement()
            self.cooldowns()

            self.get_status()
            self.animate()

            self.move()
            self.inventory.update()

        self.am_i_dead()
