import pygame
import sys
import os
from pytmx.util_pygame import load_pygame
import pytmx
from settings import *


class MapRenderer:
    def __init__(self, map_path):
        self.tmx_data = load_pygame(map_path)
        self.tile_cache = TileCache()
        self.object_group = pygame.sprite.Group()  # Group for map objects

        # Load objects into sprite group
        self.load_objects()

    def load_objects(self):
        for layer in self.tmx_data.layers:
            if isinstance(layer, pytmx.TiledObjectGroup):
                for obj in layer:
                    if obj.image:
                        map_object = MapObject(obj, [self.object_group])  # Pass object_group
    
    def get_objects(self):
        """Returns a list of all MapObject instances in the object_group."""
        return self.object_group.sprites() 

    def render(self, screen, player_position, screen_size):
        camera_x = player_position[0] - screen_size[0] // 2
        camera_y = player_position[1] - screen_size[1] // 2

        camera_x = max(0, camera_x)
        camera_x = min(
            camera_x, self.tmx_data.width * TILE_WIDTH - screen_size[0]
        )
        camera_y = max(0, camera_y)
        camera_y = min(
            camera_y, self.tmx_data.height * TILE_HEIGHT - screen_size[1]
        )

        start_x = max(0, camera_x // TILE_WIDTH)
        start_y = max(0, camera_y // TILE_HEIGHT)
        end_x = min(
            self.tmx_data.width, (camera_x + screen_size[0]) // TILE_WIDTH + 1
        )
        end_y = min(
            self.tmx_data.height, (camera_y + screen_size[1]) // TILE_HEIGHT + 1
        )

        # Render tiles
        for layer in self.tmx_data.visible_layers:
            if hasattr(layer, 'tiles'):
                for x in range(start_x, end_x):
                    for y in range(start_y, end_y):
                        surface = self.tile_cache.get_tile(
                            layer, x, y, self.tmx_data
                        )
                        if surface:
                            position = (
                                x * TILE_WIDTH - camera_x,
                                y * TILE_HEIGHT - camera_y,
                            )
                            screen.blit(surface, position)

        # Render and update map objects
        self.object_group.update(camera_x, camera_y)
        self.object_group.draw(screen)


class MapObject(pygame.sprite.Sprite): # No need to inherit from Tile
    def __init__(self, obj, groups):  # Pass 'groups' here
        super().__init__(groups)

        #if hasattr(obj, 'width') and hasattr(obj, 'height'):
        #   self.image = pygame.transform.scale(obj.image, (obj.width, obj.height))
        #else:
        #   self.image = obj.image

        self.image = obj.image

        self.rect = self.image.get_rect(topleft=(obj.x, obj.y))
        self.obj = obj  # store a reference to pytmx object

        # If you want MapObject to have hitbox and sprite_type:
        self.hitbox = self.rect.copy() # Adjust if needed
        
        self.sprite_type = OBJECT  # Set appropriate type

    def update(self, camera_x, camera_y):
        # Update position based on camera
        self.rect.x = self.obj.x - camera_x
        self.rect.y = self.obj.y - camera_y

class TileCache:
    def __init__(self):
        self.cache = {}

    def get_tile(self, layer, tile_x, tile_y, tmx_data):
        key = (layer, tile_x, tile_y)
        if key not in self.cache:
            gid = layer.data[tile_y][
                tile_x
            ]  # Access gid directly for older pytmx versions
            if gid:
                surface = tmx_data.get_tile_image_by_gid(gid)
            else:
                surface = None
            self.cache[key] = surface
        return self.cache[key]


if __name__ == "__main__":
    pygame.init()
    screen_size = (WIDTH, HEIGHT)
    player_position = [6500, 6000]
    screen = pygame.display.set_mode(screen_size)

    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)

    map_renderer = MapRenderer(
        f"{BASE_PATH}/new_map/cyber_map.tmx"
    )  # Create map renderer instance

    clock = pygame.time.Clock()

    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()

        # Handle player movement based on keyboard input (example)
        keys = pygame.key.get_pressed()
        if keys[pygame.K_LEFT]:
            player_position[0] -= 5
        if keys[pygame.K_RIGHT]:
            player_position[0] += 5
        if keys[pygame.K_UP]:
            player_position[1] -= 5
        if keys[pygame.K_DOWN]:
            player_position[1] += 5

        screen.fill("black")
        map_renderer.render(screen, player_position, screen_size)
        pygame.display.update()

        clock.tick(60)
