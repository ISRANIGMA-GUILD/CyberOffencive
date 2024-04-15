import pygame
import pyautogui
from ctypes import cast, POINTER
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
import time


class CreePy:
    def __init__(self) -> None:
        pygame.init()
        devices = AudioUtilities.GetSpeakers()

        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        self._volume = cast(interface, POINTER(IAudioEndpointVolume))
        
        self._phase: int = 0
        self._phase_duration: int = 30  # seconds

        self._phase_switch_sleep: int = 1  # seconds
        self._volume_level: float = self._volume.GetMasterVolumeLevelScalar()

        self._volume_switch_sleep: int = 1  # seconds
    
    @property
    def __MAX_PHASE(self) -> int:
        return 1
    
    @property
    def __PHASES(self) -> dict:
        return {1: self._phase_two}
    
    @property
    def __MUTE(self) -> int:
        return 1
    
    @property
    def __UNMUTE(self) -> int:
        return 0
    
    @property
    def __MAX_VOLUME_LEVEL(self) -> float:
        return 1.0
    
    @property 
    def __MIN_VOLUME_LEVEL(self) -> float:
        return 1.0
    
    def run(self) -> None:
        for _ in range(self.__MAX_PHASE):
            self.next_phase()

    def _phase_one(self) -> None:
        end_time = time.time() + self._phase_duration
        while time.time() < end_time:
            pyautogui.moveRel(xOffset=10, yOffset=10, duration=0.4)
    
    def _phase_two(self) -> None:

        self.__play_music(r'C:\\Users\\imper\\OneDrive\\Desktop\\Cyber\\gitprojects\\Git\\basic_com\\Game\\src\\code\\perfectmusic.mp3')
        self.__increase_volume(1)

        time.sleep(self._volume_switch_sleep)
        self.__update_volume()
    
    def next_phase(self) -> None:
        if self._phase < self.__MAX_PHASE:
            self._phase += 1
        time.sleep(self._phase_switch_sleep)
        self.__PHASES[self._phase]()
        
    def __play_music(self, file_path: str) -> None:
        pygame.mixer.init()
        pygame.mixer.music.load(file_path)
        pygame.mixer.music.play(0, 28.0)
    
    def __stop_music(self) -> None:
        pygame.mixer.music.stop()    
        
    def __update_volume(self) -> None:        
        self._volume.SetMute(1, None)
        
        # the range of the master volume level is 0.0 (0) to 1.0 (100)
        self._volume.SetMasterVolumeLevelScalar(1.0, None)
    
    def __increase_volume(self, inc_value: float) -> None:
        if self._volume_level + inc_value <= self.__MAX_VOLUME_LEVEL:
            self._volume_level += inc_value
            
    def __decrease_volume(self, dec_value: float) -> None:
        if self._volume_level - dec_value >= self.__MIN_VOLUME_LEVEL:
            self._volume_level -= dec_value

    def get_volume(self):
        return self._volume
