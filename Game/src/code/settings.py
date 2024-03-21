# ==== Window Settings =====
WIDTH: int = 800
HEIGTH: int = 600
# ==========================


# ==== Game Settings =====
FPS: float = 60

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
#=============================