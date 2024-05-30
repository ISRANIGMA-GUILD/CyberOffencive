import pygame
from settings import *
from tile import *
from player import *
from camera import *
from utils import *
from melee_weapon import *
from ui import *
from item import Item
from hp_fruit import HPFruit
from energy_fruit import EnergyFruit
from red_hp_fruit import RedHPFruit
from blue_energy_fruit import BlueEnergyFruit
from random import choice
from sword import *
from axe import Axe
from enemy import *
from basic_spider import BasicSpider
from blue_spider import BlueSpider
from cyan_spider import CyanSpider
from cyan_red_spider import CyanRedSpider
from blue_snow_spider import BlueSnowSpider
from red_green_spider import RedGreenSpider
from red_spider import RedSpider
from goblin import Goblin
from ranged_weapon import RangedWeapon
from bow import Bow
from arrow import Arrow
from ranged_enemy import RangedEnemy
from frenzy import Frenzy
from laser_beam import LaserBeam
from map import MapRenderer
from collisiongrid import CollisionGrid


class Level:
    def __init__(self) -> None:
        self.display_surface = pygame.display.get_surface()
        
        self.visible_sprites = YSortCameraGroup()
        self.obstacles_sprites = pygame.sprite.Group()
        self.attack_sprites = pygame.sprite.Group()
        self.attackable_sprites = pygame.sprite.Group()
        self.enemies_projectiles = pygame.sprite.Group()
        
        self.sprite_cash = {}

        self.current_attack = None

        self.map_renderer = MapRenderer(TMX_MAP_PATH)  # Create MapRenderer instance
        self.collision_grid = CollisionGrid(self.map_renderer.tmx_data.width, self.map_renderer.tmx_data.height, TILE_WIDTH, TILE_HEIGHT)
        self.create_map()
        print(self.collision_grid.grid)
        
        self.ui = UI()


                # Add TMX objects to the appropriate sprite groups
        for obj in self.map_renderer.get_objects(): 
            if obj.obj.type == 'obstacle': # Replace 'obstacle' with the actual object type from Tiled
                self.obstacles_sprites.add(obj)
            elif obj.obj.type == 'item':   # Example: add objects of type 'item' to visible_sprites
                self.visible_sprites.add(obj)


    def create_map(self) -> None:
        # *** Using the MapRenderer for map loading and object placement ***
        self.obstacles_sprites = self.map_renderer.object_group
        for obj in self.map_renderer.get_objects():
            self.collision_grid.add_to_grid(obj)
        
        self.player = Player((6000, 6000), [self.visible_sprites], self.attackable_sprites,
                             self.obstacles_sprites, self.create_attack, self.destroy_weapon,
                             f'{BASE_PATH}/graphics/player/up_idle/up_idle_0.png')

    def create_attack(self) -> None:
        self.current_attack = None # Sword(self.player, [self.visible_sprites]) # MeleeWeapon(self.player, [self.visible_sprites])
        
        
    def destroy_weapon(self) -> None:
        if self.current_attack:
            self.current_attack.kill()
        self.current_attack = None


    def player_attack_logic(self) -> None:
        
        if self.attack_sprites:
            for attack_sprite in self.attack_sprites:
                
                collision_sprites = pygame.sprite.spritecollide(attack_sprite, self.attackable_sprites, False)
                
                if collision_sprites:
                    for target_sprite in collision_sprites:
                        
                        if ENEMY == target_sprite.sprite_type:
                            target_sprite.get_damage(self.player, attack_sprite)
                    
    
    def damage_player(self, player, amount_of_damage, attack_type) -> None:
        if player.vulnerable and player.stats[HEALTH] > 0:
            #print("the player is: ", player.status)
            player.stats[HEALTH] -= amount_of_damage
            
            player.vulnerable = False
            player.hurt_time = pygame.time.get_ticks()
                        
                            
    def run(self) -> None:
        check = self.player.inventory.hotbar.content[self.player.inventory.hotbar.active_item_index]
        
        if self.player.attacking and len(check) and (check[0].__class__, MeleeWeapon):
            self.attack_sprites.add(self.player.inventory.hotbar.content[self.player.inventory.hotbar.active_item_index][0])
        
        player_active_item = self.player.inventory.hotbar.content[self.player.inventory.hotbar.active_item_index]
        
        if player_active_item and len(player_active_item):
            if not self.player.using_item and self.player.attacking:
                self.visible_sprites.add(player_active_item[0])
            
        # Let MapRenderer handle the offset during rendering
        self.map_renderer.render(self.display_surface, self.player.rect.center, (WIDTH, HEIGHT))

        self.visible_sprites.custom_draw(self.player)
        self.visible_sprites.update(self.collision_grid)
        
        self.visible_sprites.enemy_update(self.player, [self.visible_sprites, self.enemies_projectiles])
        self.player_attack_logic()
        
        self.ui.display(self.player)
        self.player.inventory.display()
        
        self.player.render_skills()
        
        if player_active_item and len(player_active_item):
           self.visible_sprites.remove(player_active_item[0])
        
        for visible_sprite in self.visible_sprites:
            if self.player.hitbox.colliderect(visible_sprite.rect) and (issubclass(visible_sprite.__class__, Fruit) or issubclass(visible_sprite.__class__, Weapon)):
                could_pickup_item = self.player.inventory.hotbar.insert(visible_sprite)
                
                if could_pickup_item:
                    self.visible_sprites.remove(visible_sprite)

            if issubclass(visible_sprite.__class__, LaserBeam):
                for obstacle_sprite in self.obstacles_sprites:
                    if visible_sprite.rect.colliderect(obstacle_sprite.rect):
                        visible_sprite.kill()
                    if visible_sprite.rect.colliderect(self.player.hitbox):
                        self.damage_player(self.player, visible_sprite.damage, '')
                        visible_sprite.kill()

                                    
        check = self.player.inventory.hotbar.content[self.player.inventory.hotbar.active_item_index]
        
        if len(check) and (check[0].__class__, MeleeWeapon):
            self.attack_sprites.remove(self.player.inventory.hotbar.content[self.player.inventory.hotbar.active_item_index][0])
            
        # check if there are Arrows that collide with some obstacles and attackable sprites:
        for attack_sprite in self.attack_sprites:
            if issubclass(attack_sprite.__class__, Arrow):
                
                for attackable_sprite in self.attackable_sprites:
                    if attack_sprite.rect.colliderect(attackable_sprite.rect):
                        attack_sprite.kill()
                        
                for obstacle_sprite in self.obstacles_sprites:
                    if attack_sprite.rect.colliderect(obstacle_sprite.rect):
                        attack_sprite.kill()