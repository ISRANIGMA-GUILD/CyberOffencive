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
	'player' : -26,
	'object' : -40,
	'grass' : -10,
	'invisible' : 0
}

INFLATE_X: int = -6
#=============================


#====== Sprite Types ========= 
INVISIBLE: str = 'invisible'
#=============================


#========== Layers ===========
BOUNDARY: str = 'boundary'
GRASS: str = 'grass'
OBJECT: str = 'object'
#=============================


#===== Useful Characters =====
COMMA: str = ','
SLASH: str = '/'
UNDERSCORE: str = '_'
#=============================

#====== Player Statuses ======
UP: str = 'up'
DOWN: str = 'down'
LEFT: str = 'left'
RIGHT: str = 'right'
ATTACK: str = '_attack'
IDLE: str = '_idle'
NO_ACTION: str = ''

HEALTH: str = 'health'
ENERGY: str = 'energy'
DAMAGE: str = 'damage'
SPEED: str = 'speed'
#=============================

#========= Weapons ===========
WEAPON_DATA: dict = {
	'sword' : {
		'cooldown' : 100,
		'damage' : 15,
		'path' : '../graphics/weapons/sword/full.png',
	},
}
#=============================

#==== Inventory Settings =====
INVENTORY_CAPACITY: int = 1 # TODO to change this value: add more weapons and items
#============================= 

#===== Useful Constants ======
INC: int = 1
DEC: int = 1
#=============================

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
PLAYER_OBJECT: str = 'player_object'
#=============================