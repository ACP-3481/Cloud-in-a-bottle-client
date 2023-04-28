from kivymd.app import MDApp
from kivy.clock import Clock
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.screenmanager import NoTransition
from kivy.core.window import Window
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDRaisedButton
import ipaddress as ipv4
import os
import configparser
import sys
from ConnectionManager import ConnectionManager
import time


class SplashScreen(Screen):
    def on_enter(self, *args):
        Clock.schedule_once(self.switch_to_home, 3)

    def switch_to_home(self, dt):
        self.manager.current = 'login'

class LoginScreen(Screen):
    dialog = None
    ip_error_dialog = None
    numeric_error_dialog = None
    range_error_dialog = None
    error = ""
    ip_address = ""
    port = -1
    password = ""
    timeout_dialog = None
    success_dialog = None
    incorrect_dialog = None
    key_errors = ["Key must be at least 12 characters long","Key must contain a lowercase letter","Key must contain an uppercase letter","Key must contain a number","Key must contain a special character"]
    def on_pre_enter(self):
        self.length_error_dialog = MDDialog(
            text=self.key_errors[0],
            buttons=[
                MDRaisedButton(
                    text="Ok",
                    on_press= lambda _: self.length_error_dialog.dismiss()
                )
            ]
        )
        self.l_case_dialog = MDDialog(
            text=self.key_errors[1],
            buttons=[
                MDRaisedButton(
                    text="Ok",
                    on_press= lambda _: self.l_case_dialog.dismiss()
                )
            ]
        )
        self.u_case_dialog = MDDialog(
            text=self.key_errors[2],
            buttons=[
                MDRaisedButton(
                    text="Ok",
                    on_press= lambda _: self.u_case_dialog.dismiss()
                )
            ]
        )
        self.num_error_dialog = MDDialog(
            text=self.key_errors[3],
            buttons=[
                MDRaisedButton(
                    text="Ok",
                    on_press= lambda _: self.num_error_dialog.dismiss()
                )
            ]
        )
        self.spec_error_dialog = MDDialog(
            text=self.key_errors[4],
            buttons=[
                MDRaisedButton(
                    text="Ok",
                    on_press= lambda _: self.spec_error_dialog.dismiss()
                )
            ]
        )

    def login_success(self):
        self.success_dialog.dismiss()
        self.manager.current = 'home'

    def login_attempt(self):
        login_value = connection.login(self.ip_address, self.port, self.password)
        self.dialog.dismiss()
        if login_value[0]:
            if not self.success_dialog:
                self.success_dialog = MDDialog(
                    text="Login Successful",
                    buttons=[
                        MDRaisedButton(
                            text="Ok",
                            on_press= lambda _: self.success_dialog.dismiss()
                        )
                    ]
                )
            self.success_dialog.open()
        else:
            if login_value[1] == "Connection Timed Out":
                if not self.timeout_dialog:
                    self.timeout_dialog = MDDialog(
                        text="Connection Timed Out\nAre the IP address and port correct?",
                        buttons=[
                            MDRaisedButton(
                                text="Ok",
                                on_press= lambda _: self.timeout_dialog.dismiss()
                            )
                        ]
                    )
                self.timeout_dialog.open()
            elif login_value[1] == "Incorrect Password":
                if not self.incorrect_dialog:
                    self.incorrect_dialog = MDDialog(
                        text="Incorrect Password",
                        buttons=[
                            MDRaisedButton(
                                text="Ok",
                                on_press= lambda _: self.incorrect_dialog.dismiss()
                            )
                        ]
                    )
                self.incorrect_dialog.open()


    def button_press(self):
        self.error = ""
        for i in range(1):
            self.ip_address = self.ids.ip.text
            try:
                ipv4.ip_address(self.ip_address)
            except ValueError:
                self.error = "Not a valid IP Address"
                if not self.ip_error_dialog:
                    self.ip_error_dialog = MDDialog(
                        text=self.error,
                        buttons=[
                            MDRaisedButton(
                                text="Cancel",
                                on_press= lambda _: self.ip_error_dialog.dismiss()
                            ),
                        ],
                    )
                self.ip_error_dialog.open()
                break
            port = self.ids.port.text
            if not port.isnumeric():
                self.error = "Port must be a number"
                if not self.numeric_error_dialog:
                    self.numeric_error_dialog = MDDialog(
                        text=self.error,
                        buttons=[
                            MDRaisedButton(
                                text="Cancel",
                                on_press= lambda _: self.numeric_error_dialog.dismiss()
                            ),
                        ],
                    )
                self.numeric_error_dialog.open()
                break
            self.port = int(port)
            if self.port not in range(0, 65537):
                self.error = "Port must be in range: 0-65536"
                if not self.range_error_dialog:
                    self.range_error_dialog = MDDialog(
                        text=self.error,
                        buttons=[
                            MDRaisedButton(
                                text="Cancel",
                                on_press= lambda _: self.range_error_dialog.dismiss()
                            ),
                        ],
                    )
                self.range_error_dialog.open()
                break
            self.error = connection.register_key(self.ids.key.text)
            if self.error != "Key registered successfully":
                index = self.key_errors.index(self.error)
                match index:
                    case 0:
                        self.length_error_dialog.open()
                    case 1:
                        self.l_case_dialog.open()
                    case 2:
                        self.u_case_dialog.open()
                    case 3:
                        self.num_error_dialog.open()
                    case 4:
                        self.spec_error_dialog.open()
                break
            else:
                self.error = ""

        self.password = self.ids.password.text
        if self.error == "":
            if not self.dialog:
                self.dialog = MDDialog(
                    text="Attempting Login, Please Wait"
                )
            self.dialog.open()
            Clock.schedule_once(lambda _: self.login_attempt(), 2)

class HomeScreen(Screen):
    def on_enter(self):
        pass
            

class ClientApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Dark"
        Window.size = (324, 576)
        sm = ScreenManager(transition=NoTransition())
        sm.add_widget(SplashScreen(name="splash"))
        sm.add_widget(LoginScreen(name="login"))
        sm.add_widget(HomeScreen(name="home"))
        return sm
    
    def on_stop(self):
        connection.quit = True
    

if __name__ == '__main__':
    connection = ConnectionManager()
    ClientApp().run()