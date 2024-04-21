from pygame.locals import *

# ==== Window Settings =====
WIDTH: int = 800
HEIGTH: int = 600
# ==========================


# ==== Game Settings =====
FPS: float = 60
FLAGS: int = DOUBLEBUF
BITS_PER_PIXEL: int = 16

# ~~~ Tile Settings ~~~
TILE_WIDTH: int = 64
TILE_HEIGHT: int = 64
# ~~~~~~~~~~~~~~~~~~~~~

# ========================


# === Collision Directions ===
HORIZONTAL: str = 'Horizontal'
VERTICAL: str = 'Vertical'
# ============================


# ==== HitBox Settings =======
PLAYER: str = 'player'

HITBOX_OFFSETS: dict = {
    'player': -26,
    'object': -40,
    'grass': -10,
    'invisible': 0
}

INFLATE_X: int = -6
# =============================


# ====== Sprite Types =========
INVISIBLE: str = 'invisible'
ENEMY: str = 'enemy'
WEAPON: str = 'weapon'
# =============================


# ========== Layers ===========
BOUNDARY: str = 'boundary'
GRASS: str = 'grass'
OBJECT: str = 'object'
PLAYER_OBJECT: str = 'player_object'
# =============================


# ===== Useful Characters =====
COMMA: str = ','
SLASH: str = '/'
UNDERSCORE: str = '_'
# =============================

# ====== Player Statuses ======
UP: str = 'up'
DOWN: str = 'down'
LEFT: str = 'left'
RIGHT: str = 'right'
ATTACK: str = '_attack'
IDLE: str = '_idle'
DEATH: str = '_death'
NO_ACTION: str = ''

HEALTH: str = 'health'
ENERGY: str = 'energy'
DAMAGE: str = 'damage'
SPEED: str = 'speed'
RESISTANCE: str = 'resistance'
# =============================

# ========= Weapons ===========
WEAPON_DATA: dict = {
    'sword': {
        'cooldown': 100,
        'damage': 15,
        'path': '../graphics/weapons/sword/full.png',
    },
}

COOLDOWN: str = 'cooldown'
PATH: str = 'path'
# =============================

# ==== Inventory Settings =====
INVENTORY_CAPACITY: int = 1  # TODO to change this value: add more weapons and items
# =============================

# ===== Hot Bar Settings ======
HOTBAR_CELL_COLOR: tuple = (35, 25, 30)
HOTBAR_OUTLINE_COLOR: str = 'black'
HOTBAR_ACTIVE_COLOR: str = 'purple'

HOTBAR_BORDER_RADIUS: int = 5

HOTBAR_OUTLINE_WIDTH: int = 3
HOTBAR_ACTIVE_WIDTH: int = 5
# =============================

# ===== Useful Constants ======
INC: int = 1
DEC: int = 1
# =============================

# ===== Items Settings ========
ON_MAP: str = 'on_map'
ON_HOTBAR: str = 'on_hotbar'
ON_INVENTORY: str = 'on_inventory'
# =============================

# = User Interface Settings ==
# ~~~ General ~~~
UI_BACKGROUND_COLOR: str = "#222222"
UI_BORDER_COLOR: str = "#111111"
UI_BORDER_ACTIVE_COLOR: str = 'gold'
TEXT_COLOR: str = '#EEEEEE'
BAR_FONT_SIZE: int = 14
BAR_FONT_COLOR: str = '#EEEEEE'

# ~~~ Health Bar ~~~
HEALTH_BAR_HEIGHT: int = 28
HEALTH_BAR_WIDTH: int = 200
HEALTH_BAR_COLOR: str = 'red'

# ~~~ Energy Bar ~~~
ENERGY_BAR_HEIGHT: int = 20
ENERGY_BAR_WIDTH: int = 140
ENERGY_BAR_COLOR: int = 'blue'

# ~~~ Font ~~~
FONT_PATH: str = '../fonts/TheWildBreathOfZelda-15Lv.ttf'
FONT_SIZE: int = 18
# =============================

# ===== Enemies Settings ======
ATTACK_RADIUS: str = 'attack_radius'
NOTICE_RADIUS: str = 'notice_radius'

SPIDER_DATA: str = {
    HEALTH: 40,
    DAMAGE: 5,
    SPEED: 5,
    RESISTANCE: 3,
    ATTACK_RADIUS: 80,
    NOTICE_RADIUS: 280,
}

ENEMIES_DATA = {
    'Spider': SPIDER_DATA,

    'BasicSpider': SPIDER_DATA,

    'BlueSpider': SPIDER_DATA,

}
# =============================
