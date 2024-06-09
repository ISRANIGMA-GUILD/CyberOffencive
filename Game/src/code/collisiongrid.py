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
        # Calculate the grid coordinates for the entire object's area
        grid_x_start = sprite.hitbox.left // self.tile_width
        grid_y_start = sprite.hitbox.top // self.tile_height
        grid_x_end = (sprite.hitbox.right // self.tile_width) + 1  # Include the rightmost tile
        grid_y_end = (sprite.hitbox.bottom // self.tile_height) + 1  # Include the bottommost tile

        # Add the object to the grid for every tile it occupies
        for grid_x in range(grid_x_start, grid_x_end):
            for grid_y in range(grid_y_start, grid_y_end):
                self.grid[grid_x][grid_y].append(sprite)