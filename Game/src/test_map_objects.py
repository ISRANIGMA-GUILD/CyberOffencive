import pygame
import sys
import os
from pytmx.util_pygame import load_pygame
import pytmx
import ctypes
user32 = ctypes.windll.user32

# ==== Window Settings =====
WIDTH: int = user32.GetSystemMetrics(0) # 800
HEIGHT: int = user32.GetSystemMetrics(1) - 50 # 600
BASE_PATH: str = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive\\'
TILE_WIDTH = 64
TILE_HEIGHT = 64

class TileCache:
    def __init__(self):
        self.cache = {}

    def get_tile(self, layer, tile_x, tile_y, tmx_data):
        key = (layer, tile_x, tile_y)
        if key not in self.cache:
            gid = layer.data[tile_y][tile_x]  # Access gid directly for older pytmx versions
            if gid:
                surface = tmx_data.get_tile_image_by_gid(gid)
            else:
                surface = None
            self.cache[key] = surface
        return self.cache[key]

def render_map(screen, tmx_data, player_position, screen_size):
    camera_x = player_position[0] - screen_size[0] // 2
    camera_y = player_position[1] - screen_size[1] // 2

    camera_x = max(0, camera_x)
    camera_x = min(camera_x, tmx_data.width * TILE_WIDTH - screen_size[0])
    camera_y = max(0, camera_y)
    camera_y = min(camera_y, tmx_data.height * TILE_HEIGHT - screen_size[1])

    # Iterate through each layer
    for layer in tmx_data.layers:
        # Render object layers
        if isinstance(layer, pytmx.TiledObjectGroup):
            for obj in layer:
                # Get the object's image if it exists
                if obj.image:
                    # Get the object's position, size, and image
                    object_x = obj.x - camera_x
                    object_y = obj.y - camera_y
                    object_width = obj.width
                    object_height = obj.height
                    #print(object_width, object_height)
                    print(obj.gid)
                    #image = pygame.transform.scale(obj.image, (object_width, object_height))

                    # Draw the object on the screen
                    screen.blit(obj.image, (object_x, object_y))

pygame.init()
screen_size = (WIDTH, HEIGHT)
player_position = [6500, 6000]  
screen = pygame.display.set_mode(screen_size)

tile_cache = TileCache()

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

tmx_data = load_pygame(f'{BASE_PATH}/new_map/cyber_map.tmx')  # Update with your map path

clock = pygame.time.Clock()

while True:
    for event in pygame.event.get():
        if pygame.QUIT == event.type:
            pygame.quit()
            sys.exit()

    screen.fill('black')
    render_map(screen, tmx_data, player_position, screen_size)
    player_position[0] += 0#100
    player_position[1] += 0#100
    pygame.display.update()

    clock.tick(60)