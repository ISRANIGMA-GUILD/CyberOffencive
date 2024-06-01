import psutil
from math import sin, cos
import os
from pygame import init
import sys

init()
x = 0

while 1:
    x += 0.01
    y = sin(x) * cos(x)
    
    process = psutil.Process(os.getpid())
    ram_usage_bytes = process.memory_info().rss  # Resident Set Size (physical memory)
    ram_usage_mb = ram_usage_bytes / (1024 * 1024) 
    print(f"RAM usage: {ram_usage_mb:.2f} MB")
    
    if y == 1:
        sys.exit()