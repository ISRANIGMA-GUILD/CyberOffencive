import pygame
from settings import *
from map import MapRenderer
from collisiongrid import CollisionGrid


class EnemyManager:
    """
    Manages a group of enemies and their movement towards players.
    """

    def __init__(self, collision_grid):  # Pass collision grid here
        self.collision_grid = collision_grid

    def update_locations(self, enemies, players):
        """
        Updates the locations of all enemies based on the nearest player.
        Also handles collision with obstacles.

        :param enemies:
        :param players: List of player tuples (name, position).
        """
        pre_enemies = enemies.copy()
        for enemy in enemies:
            enemy_pos = enemy[1]
            nearest_player = self.get_nearest_player(enemy_pos, players)

            if nearest_player:
                new_location = self.move_towards_player(enemy, nearest_player[1])
                pre_enemies[pre_enemies.index(enemy)] = (enemy[0], (int(new_location[0]), int(new_location[1])))

        return pre_enemies

    def get_player_distance_and_direction(self, enemy_pos, player_pos):
        """
        Calculates the distance and direction between an enemy and a player.

        :param enemy_pos: Enemy position (x, y).
        :param player_pos: Player position (x, y).
        :return: Tuple containing distance and direction vector.
        """

        enemy_vector = pygame.math.Vector2(enemy_pos)
        player_vector = pygame.math.Vector2(player_pos)

        distance = (player_vector - enemy_vector).magnitude()

        if distance > 0:
            direction = (player_vector - enemy_vector).normalize()
        else:
            direction = pygame.math.Vector2(0, 0)

        return distance, direction

    def get_nearest_player(self, enemy_pos, players):
        """
        Finds the nearest player to an enemy.

        :param enemy_pos: Enemy position (x, y).
        :param players: List of player tuples (name, position).
        :return: Tuple containing the nearest player (name, position) or None.
        """
        if len(players) > 0:
            nearest_player = None
            nearest_distance = float('inf')

            for player in players:
                if player is not None:
                    player_pos = player[1]
                    distance, _ = self.get_player_distance_and_direction(enemy_pos, player_pos)

                    if distance < nearest_distance:
                        nearest_distance = distance
                        nearest_player = player

            return nearest_player

    def move_towards_player(self, enemy, player_pos):
        """
        Calculates the new position of an enemy moving towards a player.
        Handles collisions with obstacles.

        :param enemy: Enemy tuple (name, position).
        :param player_pos: Player position (x, y).
        :return: New enemy position (x, y).
        """

        enemy_pos = enemy[1]
        speed = 5  # Assuming speed is a global constant

        distance, direction = self.get_player_distance_and_direction(enemy_pos, player_pos)

        if distance < 300:
            new_position = pygame.math.Vector2(enemy_pos) + direction * speed

            # Collision detection
            enemy_x, enemy_y = self.collision_grid.get_grid_coords(new_position.x, new_position.y)

            # Convert enemy_x and enemy_y to integers before using them in range
            enemy_x = int(enemy_x) 
            enemy_y = int(enemy_y) 

            new_position_rect = pygame.Rect(new_position.x, new_position.y, 1, 1)  # Create a small Rect

            for grid_x in range(enemy_x - 1, enemy_x + 2):
                for grid_y in range(enemy_y - 1, enemy_y + 2):
                    for obstacle in self.collision_grid.grid[grid_x][grid_y]:
                        if obstacle.hitbox.colliderect(new_position_rect):  # Use new_position_rect here
                            return enemy_pos  # Stop movement if collision occurs

            return (new_position.x, new_position.y)

        return enemy_pos