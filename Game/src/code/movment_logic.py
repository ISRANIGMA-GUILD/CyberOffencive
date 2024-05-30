from random import randint
import pygame


class EnemyManager:
    """
    Manages a group of enemies and their movement towards players.
    """

    def __init__(self):
        pass

    def update_locations(self, enemies, players):
        """
        Updates the locations of all enemies based on the nearest player.

        :param players: List of player tuples (name, position).
        """

        for enemy in enemies:
            enemy_pos = enemy[1]
            nearest_player = self.get_nearest_player(enemy_pos, players)

            if nearest_player:
                new_location = self.move_towards_player(enemy, nearest_player[1])
                enemy = (enemy[0], new_location)

        for i in range(0, len(enemies)):

            enemies[i] = (enemies[i][0], (int(enemies[i][1][0]), int(enemies[i][1][1])))

        print("done?", enemies)

        return enemies

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

        :param enemy: Enemy tuple (name, position).
        :param player_pos: Player position (x, y).
        :return: New enemy position (x, y).
        """

        enemy_pos = enemy[1]
        speed = 5  # Assuming speed is a global constant

        distance, direction = self.get_player_distance_and_direction(enemy_pos, player_pos)

        if distance > 0:
            new_position = pygame.math.Vector2(enemy_pos) + direction * speed
            return new_position.x, new_position.y

        return enemy_pos
