import pygame
import sys
import os
from pytmx.util_pygame import load_pygame
from functools import lru_cache
import ctypes
user32 = ctypes.windll.user32

# ==== Window Settings =====
WIDTH: int = user32.GetSystemMetrics(0) # 800
HEIGHT: int = user32.GetSystemMetrics(1) - 50 # 600
BASE_PATH: str = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\'
TILE_WIDTH = 64
TILE_HEIGHT = 64

class Tile(pygame.sprite.Sprite):
    def __init__(self, position: tuple, groups, sprite_type, surface=pygame.Surface((TILE_WIDTH, TILE_HEIGHT))) -> None:
        super().__init__(groups)
        self.sprite_type = sprite_type
        self.image = surface
        self.rect = self.image.get_rect(topleft=position)

@lru_cache(maxsize=None) 
def get_tile_surface(tmx_data, layer, tile_x, tile_y): 
    gid = layer.data[tile_y][tile_x] # Correct way for older pytmx
    if gid:  
        return tmx_data.get_tile_image_by_gid(gid)
    else: 
        return None 

def render_map(screen, tmx_data, map_sprite_group, player_position, screen_size):
    map_sprite_group.empty()

    camera_x = player_position[0] - screen_size[0] // 2
    camera_y = player_position[1] - screen_size[1] // 2
    
    camera_x = max(0, camera_x)
    camera_x = min(camera_x, tmx_data.width * TILE_WIDTH - screen_size[0])
    camera_y = max(0, camera_y)
    camera_y = min(camera_y, tmx_data.height * TILE_HEIGHT - screen_size[1])

    start_x = max(0, camera_x // TILE_WIDTH)
    start_y = max(0, camera_y // TILE_HEIGHT)
    end_x = min(tmx_data.width, (camera_x + screen_size[0]) // TILE_WIDTH + 1)
    end_y = min(tmx_data.height, (camera_y + screen_size[1]) // TILE_HEIGHT + 1)

    for layer in tmx_data.visible_layers:
        if hasattr(layer, 'tiles'):
            for x in range(start_x, end_x):
                for y in range(start_y, end_y):
                    surface = get_tile_surface(tmx_data, layer, x, y) 
                    if surface:  
                        position = (x * TILE_WIDTH - camera_x, y * TILE_HEIGHT - camera_y)
                        Tile(position, map_sprite_group, '', surface=surface)

    map_sprite_group.draw(screen)

pygame.init()
screen_size = (WIDTH, HEIGHT)
player_position = [6000, 6000]  # Initial player position
screen = pygame.display.set_mode(screen_size)

map_sprite_group = pygame.sprite.Group()

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

tmx_data = load_pygame(f'{BASE_PATH}/new_map/cyber_map.tmx') # Replace with your TMX map path

clock = pygame.time.Clock()

while True:
    for event in pygame.event.get():
        if pygame.QUIT == event.type:
            pygame.quit()
            sys.exit()

    screen.fill('black')
    render_map(screen, tmx_data, map_sprite_group, player_position, screen_size)
    player_position[0] += 0#100  # Example movement 
    player_position[1] += 0#100
    pygame.display.update()

    clock.tick(60) 