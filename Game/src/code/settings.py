from pygame.locals import *
import ctypes

try:
	user32 = ctypes.windll.user32
except:
	user32 = None
BASE_PATH: str = 'C:\\Program Files (x86)\\Common Files\\CyberOffensive'
# ==== Window Settings =====
try:
	WIDTH: int = user32.GetSystemMetrics(0) # 800
	HEIGHT: int = user32.GetSystemMetrics(1) - 50 # 600
except:
	WIDTH = 1920
	HEIGHT = 1080
HALF_WIDTH: int = WIDTH // 2 # 400
HALF_HEIGHT: int = HEIGHT // 2 # 300
# ==========================

TIMEOUT_TIME = 0.003
# ==== Game Settings =====
FPS: float = 60
FLAGS: int = DOUBLEBUF
BITS_PER_PIXEL: int = 8

# ~~~ Tile Settings ~~~
TILE_WIDTH: int = 64
TILE_HEIGHT: int = 64
# ~~~~~~~~~~~~~~~~~~~~~

# ~~~ tmx Settings ~~~
TMX_MAP_PATH = f'{BASE_PATH}/new_map/cyber_map.tmx'
# ~~~~~~~~~~~~~~~~~~~~~

# ~~ Objects Settings ~~
SMALL_OBJECTS_GIDS: list = [3205, 3207, 3208, 3211]
SMALL_OBJECTS_WIDTH: int = 64
SMALL_OBJECTS_HEIGHT: int = 64

BIG_OBJECT_GIDS: list = [3206, 3209, 3210, 3212, 3213]
BIG_OBJECTS_WIDTH: int = 128
BIG_OBJECTS_HEIGHT: int = 128

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
ENEMY: str = 'enemy'
WEAPON: str = 'weapon'
ARROW: str = 'arrow'
#=============================


#========== Layers ===========
BOUNDARY: str = 'boundary'
GRASS: str = 'grass'
OBJECT: str = 'object'
PLAYER_OBJECT: str = 'player_object'
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
DEATH: str = '_death'
NO_ACTION: str = ''

HEALTH: str = 'health'
ENERGY: str = 'energy'
DAMAGE: str = 'damage'
SPEED: str = 'speed'
RESISTANCE: str = 'resistance'
#=============================

#========= Weapons ===========
WEAPON_DATA: dict = {
	'sword' : {
		'cooldown' : 100,
		'damage' : 15,
		'path' : f'{BASE_PATH}/graphics/weapons/sword/full.png',
	},
}

COOLDOWN: str = 'cooldown'
PATH: str = 'path'
ATTACK_DISTANCE: int = 50
#=============================

#==== Inventory Settings =====
INVENTORY_CAPACITY: int = 1 # TODO to change this value: add more weapons and items
#=============================

#===== Hot Bar Settings ======
HOTBAR_CELL_COLOR: tuple = (35, 25, 30)
HOTBAR_OUTLINE_COLOR: str = 'black'
HOTBAR_ACTIVE_COLOR: str = 'purple'

HOTBAR_BORDER_RADIUS: int = 5

HOTBAR_OUTLINE_WIDTH: int = 3
HOTBAR_ACTIVE_WIDTH: int = 5
#=============================

#===== Useful Constants ======
INC: int = 1
DEC: int = 1
#=============================

#===== Items Settings ========
ON_MAP: str = 'on_map'
ON_HOTBAR: str = 'on_hotbar'
ON_INVENTORY: str = 'on_inventory'
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
FONT_PATH: str = f'{BASE_PATH}/fonts/TheWildBreathOfZelda-15Lv.ttf'
FONT_SIZE: int = 18
#=============================

#===== Enemies Settings ======
ATTACK_RADIUS: str = 'attack_radius'
NOTICE_RADIUS: str = 'notice_radius'

SPIDER_DATA: str = {
		HEALTH : 40,
		DAMAGE: 4,
		SPEED: 5,
		RESISTANCE: 3,
		ATTACK_RADIUS: 80,
		NOTICE_RADIUS: 280,
}

GOBLIN: str = 'Goblin'
FRENZY: str = 'Frenzy'

ENEMIES_DATA = {
	'Spider' : SPIDER_DATA,
 
	'BasicSpider' : SPIDER_DATA,
 
	'BlueSpider' : SPIDER_DATA,
 
 	'CyanSpider' : SPIDER_DATA,
  
	'CyanRedSpider' : SPIDER_DATA,
 
	'RedGreenSpider' : SPIDER_DATA,
 
	'RedSpider' : SPIDER_DATA,
 
	'BlueSnowSpider' : SPIDER_DATA,

	GOBLIN : {
		HEALTH : 60,
		DAMAGE: 7,
		SPEED: 2,
		RESISTANCE: 3,
		ATTACK_RADIUS: 100,
		NOTICE_RADIUS: 360,
	},
 
	FRENZY : {
		HEALTH : 50,
		DAMAGE : 5,
		SPEED : 3,
		RESISTANCE : 5,
		ATTACK_RADIUS : 200,
		NOTICE_RADIUS : 900,
	},

 
}
#=============================

#===== Skills Settings =======
SKILLS_BORDER_RADIUS: int = 5
SKILLS_OUTLINE_WIDTH: int = 3
SKILLS_OUTLINE_COLOR: str = 'black'
SKILLS_ACTIVE_OUTLINE_COLOR: str = 'green'
SKILLS_ACTIVE_OUTLINE_WIDTH: int = 7
SKILLS_COOLDOWN_OUTLINE_COLOR: str = 'red'
SKILLS_COOLDOWN_OUTLINE_WIDTH: int = 7

SKILL_ENERGY_COST: str = 'energy_cost'
SKILL_ICON_PATH: str = 'icon_path'
SKILL_APPLY_FUNC: str = 'apply'
SKILL_COOLDOWN_DURATION: str = 'cooldown_duration'
SKILL_ACTIVE_DURATION: str = 'active_duration'
SKILL_APPLY_TIME: str = 'apply_time'
SKILL_APPLIED: str = 'applied'
SKILL_ACTIVE: str = 'active'

ATTACK_BOOST_SKILL_INDEX: int = 1
SPEED_BOOST_SKILL_INDEX: int = 2
REGENERATION_SKILL_INDEX: int = 3

#=============================

# === Bullet Settings ===
BULLET_SIZE: int = 8
BULLET_COLOR: tuple = (255, 255, 255)
BULLET_SPEED: int = 10
# =======================


