import pygame
from settings import *
from tile import *
from player import *
from camera import *
from utils import *
from random import choice


class Level:
    def __init__(self) -> None:
        self.display_surface = pygame.display.get_surface()
        
        self.visible_sprites = YSortCameraGroup()
        self.obstacles_sprites = pygame.sprite.Group()
        
        self.create_map()
    
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

        self.player = Player((2000, 1500), [self.visible_sprites], self.obstacles_sprites, '../graphics/brawn_idle.png')    

    def run(self) -> None:
        self.visible_sprites.custom_draw(self.player)
        self.visible_sprites.update()