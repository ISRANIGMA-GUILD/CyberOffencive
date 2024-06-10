import os
import hashlib
import ctypes
import sys
import time
import psutil

class CodeIntegrityChecker:
    def __init__(self):
        self.frame_count = 0

    def check_for_cheat_engine(self):
        """Checks if Cheat Engine is running every 60th frame."""
        if self.frame_count % 60 == 0:
            cheat_engine_substrings = {"cheatengine", "cheat engine"}
            for process in psutil.process_iter(['name']):
                try:
                    process_name = process.info['name'].lower()  # Convert to lowercase for case-insensitive matching
                    if any(substring in process_name for substring in cheat_engine_substrings):
                        print("WARNING: Cheat Engine is running!")
                        # Take action here
                        ctypes.windll.user32.MessageBoxW(0, "Cheat Engine is running. Exiting...", "Error", 1)
                        sys.exit()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

    def update(self):
        """Called every frame to perform checks."""
        self.check_for_cheat_engine()
        self.frame_count += 1

