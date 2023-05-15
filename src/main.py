from kivymd.app import MDApp
from kivy.clock import Clock
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.screenmanager import NoTransition
from kivy.core.window import Window
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDRaisedButton, MDIconButton, MDFlatButton
import ipaddress as ipv4
import os
from ConnectionManager import ConnectionManager
from kivymd.uix.filemanager import MDFileManager
import time
from kivymd.uix.list import OneLineIconListItem, IconLeftWidget
from kivymd.uix.floatlayout import MDFloatLayout
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from functools import partial
import secrets


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
        self.manager.current = 'download'

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
                            on_press= lambda _: self.login_success()
                        )
                    ]
                )
            self.success_dialog.open()
        else:
            if login_value[1] == "Connection Timed Out":
                if not self.timeout_dialog:
                    self.timeout_dialog = MDDialog(
                        text="Connection Timed Out\nAre the IP address and port correct?\nPlease try again",
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
                if index == 0:
                    self.length_error_dialog.open()
                elif index == 1:
                    self.l_case_dialog.open()
                elif index == 2:
                    self.u_case_dialog.open()
                elif index == 3:
                    self.num_error_dialog.open()
                elif index == 4:
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

class DownloadLocation(Screen):
    dialog=None
    def __init__(self, **kwargs):
        super(DownloadLocation, self).__init__(**kwargs)
        self.layout = MDFloatLayout()

        self.title = MDLabel(text="Choose a Folder to Store Cloud Storage Files", pos_hint={'center_x': 0.5,'center_y': 0.9}, width=self.width, halign='center', font_style='H5')
        self.layout.add_widget(self.title)

        # Create a button to open the file manager
        self.file_manager_button = MDRaisedButton(text="Select Folder", on_release=lambda _: self.show_file_manager(), pos_hint={'center_x': 0.5,'center_y': 0.8})
        self.layout.add_widget(self.file_manager_button)

        # Create a label to display the selected folder path
        self.folder_path_label = MDLabel(text="No folder selected yet", pos_hint={'center_x': 0.5,'center_y': 0.5}, width=self.width, halign='center')
        self.layout.add_widget(self.folder_path_label)

        # Create a button to go to the next screen
        self.next_button = MDRaisedButton(text="Next", on_release=self.go_to_next_screen, disabled=True, pos_hint={'center_x': 0.5,'center_y': 0.2})
        self.layout.add_widget(self.next_button)

        self.add_widget(self.layout)

    def show_file_manager(self, *args):
        # Create a file manager instance
        self.file_manager = MDFileManager(
            exit_manager=self.exit_file_manager,
            select_path=self.select_folder_path,
        )
        self.file_manager.add_widget(
            MDIconButton(
                icon="folder-plus",
                on_press=lambda _: self.show_dialog()
            )
                
        )
        if len(args) == 0:
            self.file_manager.show(os.getcwd().replace('\\', '/')) 
        else:
            self.file_manager.show(args[0])
    
    def select_folder_path(self, path):
        # Update the folder path label with the selected path
        self.folder_path_label.text = f"Selected folder: {path}"

        # Enable the "Next" button
        self.next_button.disabled = False

        self.exit_file_manager()
    
    def go_to_next_screen(self, *args):
        # Get a reference to the screen manager
        screen_manager = self.parent
        connection.download_path = self.file_manager.current_path
        # Go to the next screen in the screen manager
        screen_manager.current = 'home'
    
    def exit_file_manager(self, *args):
        # Close the file manager
        self.file_manager.close()
    
    def dialog_ok(self):
        folder_name = self.dialog.content_cls.ids.folder_name_field.text
        folder_path = self.file_manager.current_path + "/" + folder_name
        os.mkdir(folder_path)
        self.exit_file_manager()
        self.show_file_manager(folder_path)
        self.dialog.dismiss()

    def show_dialog(self):
        if not self.dialog:
            self.dialog = MDDialog(
                title="Dialog Title",
                type="custom",
                content_cls=DialogContent(),
                buttons=[
                    MDFlatButton(
                        text="CANCEL", on_release= lambda _: self.dialog.dismiss()
                    ),
                    MDFlatButton(
                        text="OK", on_release= lambda _: self.dialog_ok()
                    ),
                ],
            )
        self.dialog.open()

class DialogContent(MDBoxLayout):
    pass

class HomeScreen(Screen):
    filelist = []
    dialog = None
    file_dialog = None
    events = {}

    def on_pre_enter(self):
        self.ids.main_list.clear_widgets()
        self.filelist = connection.update()
        widget_list = []
        for i in self.filelist:
            Clock.schedule_once(partial(self.add_file_item, i), 0.1)

    def add_file_item(self, name: str, *args):
        widget = OneLineIconListItem(
            IconLeftWidget(
                icon='file'
            ),
            text=name,
            on_release=lambda _: self.open_download_dialog(name)
        )
        self.ids.main_list.add_widget(widget)

    def open_download_dialog(self, filename):
        self.dialog = MDDialog(
            text=f'Do you want to download "{filename}"?',
            buttons=[
                MDRaisedButton(
                    text="No",
                    on_press= lambda _: self.dialog.dismiss()
                ),
                MDRaisedButton(
                    text="Yes",
                    on_press= lambda _: self.yes_download(filename)
                )
                ],
        )
        self.dialog.open()

    def yes_download(self, filename):
        self.dialog.dismiss()
        id = secrets.token_hex(16)
        connection.download(filename, id)
        self.events[id] = Clock.schedule_interval(partial(self.check_download, id, filename), 0.5)

    def check_download(self, id, filename, *args):
        for i in connection.event_queue_info:
            if i[1] == id:
                still_in_queue = True
                break
        else:
            still_in_queue = False
        if not still_in_queue:
            self.events[id].cancel()
            self.events.pop(id)

    def upload_file(self):
        self.show_file_manager()

    def show_file_manager(self, *args):
        # Create a file manager instance
        self.file_manager = MDFileManager(
            exit_manager=lambda _: self.file_manager.close(),
            select_path=self.select_folder_path,
        )
        if len(args) == 0:
            self.file_manager.show(os.getcwd().replace('\\', '/')) 
        else:
            self.file_manager.show(args[0])
    
    def select_folder_path(self, path):
        # Update the folder path label with the selected path
        self.file_manager.close()
        if os.path.isfile(path):
            filename = path[path.rindex("\\")+1:]
            self.file_dialog = MDDialog(
                text=f'Upload {filename}?',
                buttons=[
                    MDRaisedButton(
                        text="No",
                        on_press=lambda _: self.file_dialog.dismiss()
                    ),
                    MDRaisedButton(
                        text="Yes",
                        on_press=lambda _: self.upload_yes(path, filename)
                    )
                ]
            )
        else:
            self.file_dialog = MDDialog(
                text="Selected path is not a file",
                buttons=[
                    MDRaisedButton(
                        text="Ok",
                        on_press=lambda _: self.file_dialog.dismiss()
                    )
                ]
            )
        self.file_dialog.open()

    def upload_yes(self, path, filename):
        self.file_dialog.dismiss()
        id = secrets.token_hex(16)
        connection.upload(path, id)
        self.events[id] = Clock.schedule_interval(partial(self.check_upload, id, filename), 0.5)
        
    
    def check_upload(self, id, filename, *args):
        for i in connection.event_queue_info:
            if i[1] == id:
                still_in_queue = True
                break
        else:
            still_in_queue = False
        if not still_in_queue:
            self.events[id].cancel()
            self.events.pop(id)
            self.ids.main_list.add_widget(
                OneLineIconListItem(
                    IconLeftWidget(
                            icon="file"
                    ),
                    text=filename,
                    on_release=lambda _: self.open_download_dialog(filename),
                )
            )
        


class ClientApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Dark"
        Window.size = (324, 576)
        sm = ScreenManager(transition=NoTransition())
        sm.add_widget(SplashScreen(name="splash"))
        sm.add_widget(LoginScreen(name="login"))
        sm.add_widget(DownloadLocation(name="download"))
        sm.add_widget(HomeScreen(name="home"))
        return sm
    
    def on_stop(self):
        connection.quit = True

    def key_input(self, window, key, scancode, codepoint, modifier):
      if key == 27:
         return True  # override the default behaviour
      else:           # the key now does nothing
         return False
      
    def on_pause(self):
        return True
    

if __name__ == '__main__':
    connection = ConnectionManager()
    ClientApp().run()
