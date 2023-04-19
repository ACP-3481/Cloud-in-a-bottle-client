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
        cipher_padded = (cipher_text_b32.decode() + " "*size_difference)
        self._increment_nonce()
        return cipher_padded
    
    def _decrypt_with_padding(self, data: bytes):
        decrypted = self.session_cipher.decrypt(base64.b32decode(data.decode().strip().encode()))
        self._increment_nonce()
        return decrypted



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
            elif response == "Correct Password":
                self.message = "Correct Password"
                self.logged_in = True
        
        while self.logged_in:
            if self.quit:
                break
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
        
    
    def quit(self):
        self.quit = True
