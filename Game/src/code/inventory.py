from settings import *
from hotbar import *

class Inventory:
    def __init__(self, rows: int, cols: int) -> None:
        self.hotbar = HotBar(5)
        self.is_open = False
        
    
    def update(self) -> None:
        self.hotbar.update()
        
        if not self.is_open:
            return
    
    
    def display(self) -> None:
        self.hotbar.display()    
        
        if not self.is_open:
            return
        
    def has_weapon(self) -> bool:
        return self.hotbar.has_weapon()