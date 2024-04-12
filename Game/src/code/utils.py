import pygame
from csv import reader
from os import walk
from settings import *


def import_csv_layout(path: str) -> list:
    terrain_map = []

    with open(path) as map_file:
        layout = reader(map_file, delimiter=COMMA)
        for row in layout:
            terrain_map.append(list(row))

    return terrain_map


def import_folder(path: str) -> list:
    surfaces_list = []

    file_names = next(walk(path), (None, None, []))[2]  # [] if no file
    for file_name in file_names:
        full_path = path + SLASH + file_name

        image_surface = pygame.image.load(full_path).convert_alpha()
        surfaces_list.append(image_surface)

    return surfaces_list
