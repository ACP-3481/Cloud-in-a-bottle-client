from kivymd.app import MDApp
from kivy.clock import Clock
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.core.window import Window
import os
from UI import *
import configparser
import sys


class ClientApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Dark"
        Window.size = (324, 576)
        sm = ScreenManager()
        return sm
    

if __name__ == '__main__':
    ClientApp().run()