# Separate class for collision grid
class CollisionGrid:
    def __init__(self, map_width, map_height, tile_width, tile_height):
        self.grid = [[[] for _ in range(map_height)] for _ in range(map_width)]
        self.tile_width = tile_width
        self.tile_height = tile_height

    def get_grid_coords(self, x, y):
        grid_x = x // self.tile_width
        grid_y = y // self.tile_height
        return grid_x, grid_y

    def add_to_grid(self, sprite):
        grid_x, grid_y = self.get_grid_coords(sprite.hitbox.centerx, sprite.hitbox.centery)
        self.grid[grid_x][grid_y].append(sprite)