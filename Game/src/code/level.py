import pygame
from settings import *
from tile import *
from player import *
from camera import *
from utils import *
from melee_weapon import *
from ui import *
from item import *
from hp_fruit import *
from energy_fruit import *
from random import choice
from sword import *
from enemy import *
from basic_spider import *
from blue_spider import *

class Level:
    def __init__(self) -> None:
        self.display_surface = pygame.display.get_surface()
        
        self.visible_sprites = YSortCameraGroup()
        self.obstacles_sprites = pygame.sprite.Group()
        self.attack_sprites = pygame.sprite.Group()
        self.attackable_sprites = pygame.sprite.Group()
        
        
        self.current_attack = None
        
        self.create_map()
        
        self.ui = UI()


    def create_map(self) -> None:
        layouts = {
            BOUNDARY : import_csv_layout('../map/FloorBlocks.csv'),
            GRASS : import_csv_layout('../map/Grass.csv'),
            OBJECT : import_csv_layout('../map/Objects.csv'),
        }

        
        graphics = {
            GRASS : import_folder('../graphics/grass'),
            OBJECT : import_folder('../graphics/objects'),
            #../graphics/summer/objects
        }


        for layer, layout in layouts.items():
            for row_index, row in enumerate(layout):
                for col_index, col in enumerate(row):
                    if col != '-1':
                        x = col_index * TILE_WIDTH
                        y = row_index * TILE_HEIGHT

                        if BOUNDARY == layer:
                            Tile((x, y), [self.obstacles_sprites], INVISIBLE)
                        elif GRASS == layer:
                            random_grass_image = choice(graphics[GRASS])
                            Tile((x, y), [self.visible_sprites, self.obstacles_sprites], GRASS, random_grass_image)
                        elif OBJECT == layer:
                            object_surface = graphics[OBJECT][int(col)]
                            Tile((x, y), [self.visible_sprites, self.obstacles_sprites], OBJECT, object_surface)
                            
        HPFruit((1900, 1500), [self.visible_sprites])
        HPFruit((1900, 1580), [self.visible_sprites])
        EnergyFruit((1950, 1700), [self.visible_sprites])
        Sword((1900, 1550), [self.visible_sprites])
        Sword((1500, 1670), [self.visible_sprites])
        
        BasicSpider((1100, 1500), [self.visible_sprites, self.attackable_sprites], self.obstacles_sprites, self.damage_player, self)
        BlueSpider((2000, 900), [self.visible_sprites, self.attackable_sprites], self.obstacles_sprites, self.damage_player, self)
        
        self.player = Player((2500, 1500), [self.visible_sprites], self.obstacles_sprites, self.create_attack, self.destroy_weapon, '../graphics/brawn_idle.png')    
        #self.player.inventory.hotbar.insert(HPFruit((2000, 1680), [self.visible_sprites]))


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
                            target_sprite.get_damage(self.player, attack_sprite.sprite_type)
                    
    
    def damage_player(self, player, amount_of_damage, attack_type) -> None:
        if player.vulnerable:
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
            
        self.visible_sprites.custom_draw(self.player)
        self.visible_sprites.update()
        self.visible_sprites.enemy_update(self.player)
        self.player_attack_logic()
        self.ui.display(self.player)
        self.player.inventory.display()
        
        if player_active_item and len(player_active_item):
           self.visible_sprites.remove(player_active_item[0])
        
        for visible_sprite in self.visible_sprites:
            if self.player.hitbox.colliderect(visible_sprite.rect) and visible_sprite.__class__ in [HPFruit, EnergyFruit, Sword]:
                self.player.inventory.hotbar.insert(visible_sprite)
                self.visible_sprites.remove(visible_sprite)
        
        check = self.player.inventory.hotbar.content[self.player.inventory.hotbar.active_item_index]
        if len(check) and (check[0].__class__, MeleeWeapon):
            self.attack_sprites.remove(self.player.inventory.hotbar.content[self.player.inventory.hotbar.active_item_index][0])
