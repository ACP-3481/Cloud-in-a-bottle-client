import json
import socket
import os
import sys
from Crypto.Cipher import AES
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import secrets
import tkinter as tk
from tkinter import filedialog
import re
import hashlib
import threading
import time
from typing import Optional
import binascii


class ConnectionManager:
    
    def __init__(self):
        self.logged_in = False
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.settimeout(5)
        self.host = ""
        self.port = -1
        self.error = ""
        self.password = ""
        self.message = ""
        self.quit = False

        self.nonce_int = None
        self.nonce = None
        self.session_cipher = None
        self.session_key = None
        self.client_key = None
        self.client_cipher = None

        self.update_dict = None
        self.filenames = None
        self.filename_b32_list = None

        self.download_path = None
        self.download_in_progress = False
        self.upload_in_progress = False
        self.event_queue = []
        self.event_queue_info = []

        main = threading.Thread(target=self.main_process)
        main.start()

    def _increment_nonce(self):
            self.nonce_int += 1
            self.nonce = self.nonce_int.to_bytes(32, 'big')
            self.session_cipher = AES.new(self.session_key, AES.MODE_EAX, self.nonce)

    def _decrement_nonce(self):
        self.nonce_int -= 1
        self.nonce = self.nonce_int.to_bytes(32, 'big')
        self.session_cipher = AES.new(self.session_key, AES.MODE_EAX, self.nonce)

    def _encrypt_with_padding(self, data: bytes):
        cipher_text = self.session_cipher.encrypt(data)
        cipher_text_b32 = base64.b32encode(cipher_text)
        size_difference = 1024 - (sys.getsizeof(cipher_text_b32) % 1024)
        cipher_padded = (cipher_text_b32.decode() + " "*size_difference).encode()
        self._increment_nonce()
        return cipher_padded
    
    def _decrypt_with_padding(self, data: bytes):
        try:
            decrypted = self.session_cipher.decrypt(base64.b32decode(data.decode().strip().encode()))
            self._increment_nonce()
            return decrypted
        except binascii.Error as e:
            print('data recieved')
            print(data.decode())
            print('end recieve')
            raise e
    
    def _renew_client_cipher(self, nonce : Optional[int]=None):
        if nonce is not None:
            self.client_cipher = AES.new(self.client_key, AES.MODE_EAX, nonce)
        else:
            self.client_cipher = AES.new(self.client_key, AES.MODE_EAX)



    def main_process(self):
        

        while not self.logged_in:
            time.sleep(0.5)
            if self.quit:
                break

            if self.host == "" or self.port == -1:
                continue
            try:
                self.server.connect((self.host, self.port))
            except socket.error as exc:
                if type(exc) is TimeoutError:
                    self.error = "Connection Timed Out"
                    self.host = ""
                    self.port = -1
                    continue
            
            rsa_key = self.server.recv(1024)
            rsa_key = RSA.import_key(rsa_key.decode().strip())
            rsa_encryptor = PKCS1_OAEP.new(rsa_key)
            self.session_key = secrets.token_bytes(16)
            encrypted_key = rsa_encryptor.encrypt(self.session_key)
            encrypted_key = base64.b32encode(encrypted_key)
            key_size = sys.getsizeof(encrypted_key)
            size_difference = 1024 - key_size
            encrypted_key = (encrypted_key.decode() + " "*size_difference).encode()
            self.server.send(encrypted_key)
            self.nonce_int = 0
            self.nonce = self.nonce_int.to_bytes(32, 'big')
    
            self.session_cipher = AES.new(self.session_key, AES.MODE_EAX, self.nonce)
            self.server.send(self._encrypt_with_padding(self.password.encode()))

            response = self._decrypt_with_padding(self.server.recv(1024)).decode()
            if response == "Incorrect Password":
                self.error = "Incorrect Password"
                self.password = ""
                self.host = ""
                self.port = -1
                self.server.close()
                self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server.settimeout(5)
            elif response == "Correct Password":
                self.message = "Correct Password"
                self.logged_in = True
        
        while self.logged_in:
            if self.quit:
                break
            match self.event_queue[0]:
                case "Download":
                    pass
                case "Upload":
                    pass


    def login(self, ip, port, password):
        self.host = ip
        self.port = port
        self.password = password
        while True:
            time.sleep(0.5)
            if self.error != "":
                login_error = self.error
                self.error = ""
                return False, login_error
            if self.message != "":
                login_complete = self.message
                self.message = ""
                return True, login_complete
        
    def update(self):
        self.server.send(self._encrypt_with_padding(b'Update'))
        data = self.server.recv(1024)
        data = self._decrypt_with_padding(data)
        update_size = int(data.decode())
        update_data = self._decrypt_with_padding(self.server.recv(update_size))
        self.update_dict = json.loads(update_data)
        
        self.filenames = []
        self.filename_b32_list = []
        for item in self.update_dict:
            self.filename_b32_list.append(item)
            filename_bytes = base64.b32decode(item)
            filename_nonce_bytes = base64.b32decode(self.update_dict[item])
            self._renew_client_cipher(filename_nonce_bytes)
            self.filenames.append(self.client_cipher.decrypt(filename_bytes).decode())
        
        self._renew_client_cipher()
        
        return self.filenames

    def upload(self, upload_file: str, id):
        self.event_queue.append("Upload")
        self.event_queue_info.append([upload_file, id])

        self.upload_in_progress = True
        self.server.send(self._encrypt_with_padding(b'Upload'))
        filename = upload_file[(upload_file.rindex("\\") + 1):]
        with open(upload_file, 'rb') as file:
            data = file.read()

        client_ciphered_data = self.client_cipher.encrypt(data)
        data_nonce = base64.b32encode(self.client_cipher.nonce)
        self._renew_client_cipher()

        self._increment_nonce()
        session_ciphered_data = self.session_cipher.encrypt(client_ciphered_data)
        self._decrement_nonce()

        data_size = sys.getsizeof(client_ciphered_data)
        ciphered_filename =  base64.b32encode(self.client_cipher.encrypt(filename.encode()))
        self.filenames.append(filename)
        self.filename_b32_list.append(ciphered_filename.decode())
        filename_nonce = base64.b32encode(self.client_cipher.nonce)
        self._renew_client_cipher()

        leading_message = self._encrypt_with_padding(ciphered_filename+b'|'+filename_nonce+b'|'+data_nonce+b'|'+str(data_size).encode())
        self.server.send(leading_message)
        self._increment_nonce()
        self.server.send(session_ciphered_data)

        self.upload_in_progress = False

    def download(self, filename, id):
        self.event_queue.append("Download")
        self.event_queue_info.append([filename, id])

        if filename not in self.filenames:
            # this has to pull up en error dialog on the screen
            return
        file_to_download_b32 = self.filename_b32_list[self.filenames.index(filename)].encode()

        self.server.send(self._encrypt_with_padding(b'Download'))
        self.server.send(self._encrypt_with_padding(file_to_download_b32))

        data_hold = self.server.recv(1024)
        data_hold2 = self._decrypt_with_padding(data_hold)
        data_size, data_nonce_b32 = data_hold2.decode().split("|")
        data_size = int(data_size)
        data_nonce = base64.b32decode(data_nonce_b32)

        data_ciphered = self.session_cipher.decrypt(self.server.recv(data_size))
        self._increment_nonce()

        self._renew_client_cipher(data_nonce)
        file_data = self.client_cipher.decrypt(data_ciphered)
        self._renew_client_cipher()

        with open(f'{self.download_path}/{filename}', 'wb') as f:
            f.write(file_data)
        
        

    def register_key(self, key: str):
        if len(key) < 12:
            return "Key must be at least 12 characters long"
        elif not re.search("[a-z]", key):
            return "Key must contain a lowercase letter"
        elif not re.search("[A-Z]", key):
            return "Key must contain an uppercase letter"
        elif not re.search("[0-9]", key):
            return "Key must contain a number"
        elif not re.search("[ !\"#$%&'()*+,-./:;\\<=>?@[\]^_`{|}~]" , key):
            return "Key must contain a special character"
        else:
            self.client_key = hashlib.sha256(key.encode()).digest()
            self.client_cipher = AES.new(self.client_key, AES.MODE_EAX)
            return "Key registered successfully"
        
        

    def quit(self):
        self.quit = True
