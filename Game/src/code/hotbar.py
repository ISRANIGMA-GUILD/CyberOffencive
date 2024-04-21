from settings import *
from item import *
from fruit import *
from weapon import *


class HotBar:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.content = [[] for _ in range(self.capacity)]

        self.active_item_index = 0
        self.__font = pygame.font.Font(FONT_PATH, 24)

    
    def apply_active_item(self, player) -> None:

        if len(self.content[self.active_item_index]) and issubclass(self.content[self.active_item_index][0].__class__, Fruit):
            self.content[self.active_item_index][0].apply(player)
            self.content[self.active_item_index].pop()
    
    
    def decrease_active_item_index(self) -> None:

        self.active_item_index = (self.active_item_index - DEC) % self.capacity
    
    
    def increase_active_item_index(self) -> None:

        self.active_item_index = (self.active_item_index + INC) % self.capacity
    
    
    def insert(self, item: Item) -> bool:

        for i in range(self.capacity):
            if not len(self.content[i]) or (not issubclass(item.__class__, Weapon) and
                                            item.__class__ == self.content[i][0].__class__):
                self.content[i].append(item)
                return True

        return False

    def update(self) -> None:
        pass
    
    def display(self) -> None:
        surface = pygame.display.get_surface()
                
        for i in range(self.capacity):
            ri = pygame.Rect(30 + i * 50 + i * 20, 470, 50, 50)
            pygame.draw.rect(surface, HOTBAR_CELL_COLOR, ri, border_radius = HOTBAR_BORDER_RADIUS)

            if self.active_item_index == i:
                pygame.draw.rect(surface, HOTBAR_ACTIVE_COLOR, ri, border_radius = HOTBAR_BORDER_RADIUS, width = HOTBAR_ACTIVE_WIDTH)

            pygame.draw.rect(surface, HOTBAR_OUTLINE_COLOR, ri, border_radius = HOTBAR_BORDER_RADIUS, width = HOTBAR_OUTLINE_WIDTH)
            
            if len(self.content[i]):
                on_hotbar_item_image = pygame.image.load(self.content[i][0].image_paths[ON_HOTBAR]).convert_alpha()
                surface.blit(on_hotbar_item_image, (40 + i * 50 + i * 20, 478))
                
                amount_text = str(len(self.content[i]))
                rendered_amount_text = self.__font.render(amount_text, True, 'white')

                rendered_amount_text_rect = rendered_amount_text.get_rect()
                rendered_amount_text_rect.topleft = (64 + i * 50 + i * 20, 474)
                
                surface.blit(rendered_amount_text, rendered_amount_text_rect)
