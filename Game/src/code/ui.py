import pygame
from settings import *

class UI:
    def __init__(self) -> None:
        self.__display_surface = pygame.display.get_surface()
        self.__font = pygame.font.Font(FONT_PATH, size=BAR_FONT_SIZE)
        self.__font.set_bold(True)
    
        self.__health_bar_rect = pygame.Rect(10, 10, HEALTH_BAR_WIDTH, HEALTH_BAR_HEIGHT)
        self.__energy_bar_rect = pygame.Rect(10, 10 + HEALTH_BAR_HEIGHT * 1.5, ENERGY_BAR_WIDTH, ENERGY_BAR_HEIGHT)
        
    
    def show_bar(self, current_value: float, max_value: float, background_rect, color_start: tuple, color_end: tuple, text_title: str) -> None:
        pygame.draw.rect(self.__display_surface, UI_BACKGROUND_COLOR, background_rect)
        
        ratio = current_value / max_value
        normalized_width = int(background_rect.width * ratio)
        
        # Draw gradient
        for i in range(normalized_width):
            # Calculate the color at this point
            interp_ratio = i / normalized_width
            gradient_color = [int(color_start[j] + (color_end[j] - color_start[j]) * interp_ratio) for j in range(3)]
            
            # Draw a line at this point with the calculated color
            pygame.draw.line(self.__display_surface, gradient_color, 
                             (background_rect.x + i, background_rect.y), 
                             (background_rect.x + i, background_rect.y + background_rect.height))
        
        pygame.draw.rect(self.__display_surface, UI_BORDER_COLOR, background_rect, 3) # draw boundary for rect
        
        
        text = text_title + " :    " + str(current_value) + " / " + str(max_value)
        rendered_text = self.__font.render(text, True, BAR_FONT_COLOR)
        rendered_text_rect = rendered_text.get_rect()
        rendered_text_rect.center = (background_rect.centerx - 10 * ratio, background_rect.centery)
        self.__display_surface.blit(rendered_text, rendered_text_rect)
        
    
    def display(self, player) -> None:
        self.show_bar(player.stats[HEALTH], player.max_stats[HEALTH], self.__health_bar_rect, (128, 0, 0), (255, 0, 0), "Health")
        self.show_bar(player.stats[ENERGY], player.max_stats[ENERGY], self.__energy_bar_rect, (0, 0, 200), (0, 255, 255), "Energy")
