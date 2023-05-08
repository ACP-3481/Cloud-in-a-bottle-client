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
import binascii


if __name__ == '__main__':
    host = input("Host ip: ")
    port = int(input("Host Port: "))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(5)
    try:
        server.connect((host, port))
    except socket.error as exc:
        if type(exc) is TimeoutError:
            print("Connection Timed Out")
        sys.exit()

    rsa_key = server.recv(1024)
    rsa_key = RSA.import_key(rsa_key.decode().strip())
    rsa_encryptor = PKCS1_OAEP.new(rsa_key)

    session_key = secrets.token_bytes(16)
    encrypted_key = rsa_encryptor.encrypt(session_key)
    encrypted_key = base64.b32encode(encrypted_key)
    key_size = sys.getsizeof(encrypted_key)
    size_difference = 1024 - key_size
    encrypted_key = (encrypted_key.decode() + " "*size_difference).encode()

    server.send(encrypted_key)
    nonce_int = 0
    nonce = nonce_int.to_bytes(32, 'big')
    
    session_cipher = AES.new(session_key, AES.MODE_EAX, nonce)
    def increment_nonce():
        global nonce_int, nonce, session_cipher
        nonce_int += 1
        print("nonce: ", nonce_int)
        nonce = nonce_int.to_bytes(32, 'big')
        session_cipher = AES.new(session_key, AES.MODE_EAX, nonce)
    def decrement_nonce():
        global nonce_int, nonce, session_cipher
        nonce_int -= 1
        print("nonce: ", nonce_int)
        nonce = nonce_int.to_bytes(32, 'big')
        session_cipher = AES.new(session_key, AES.MODE_EAX, nonce)
    def encrypt_with_padding(data: bytes, session_cipher):
        #if the bytesize of data is 615 or less it will fit within 1024 bytes

        cipher_text = session_cipher.encrypt(data)
        cipher_text_b32 = base64.b32encode(cipher_text)
        size_difference = 1024 - (sys.getsizeof(cipher_text_b32) % 1024)
        cipher_padded = (cipher_text_b32.decode() + " "*size_difference).encode()
        return cipher_padded
    
    def decrypt_with_padding(data: bytes, session_cipher):
        try:
            return session_cipher.decrypt(base64.b32decode(data.decode().strip().encode()))
        except binascii.Error as e:
            print('data recieved')
            print(data.decode())
            print('end recieve')
            raise e

    
    password = str(input("Password: "))
    server.send(encrypt_with_padding(password.encode(), session_cipher))
    increment_nonce()

    response = decrypt_with_padding(server.recv(1024), session_cipher).decode()
    increment_nonce()
    
    if response == "Incorrect Password":
        sys.exit()
    elif response == "Correct Password":
        print(response)
    else:
        sys.exit()

    my_password = ""
    print("""Input a password to encrypt files with.
        It must be at least 12 characters long.
        It must contain a lowercase, uppercase, number, and special character.
        """)
    while True:
        my_password = str(input("File encryption key: "))
        if len(my_password) < 12:
            print("Password must be at least 12 characters long")
            continue
        elif not re.search("[a-z]", my_password):
            print("Password must contain a lowercase letter")
            continue
        elif not re.search("[A-Z]", my_password):
            print("Password must contain an uppercase letter")
            continue
        elif not re.search("[0-9]", my_password):
            print("Password must contain a number")
            continue
        elif not re.search("[ !\"#$%&'()*+,-./:;\\<=>?@[\]^_`{|}~]" , my_password):
            print("Password must contain a special character")
            continue
        break
    print("Select a folder to save downloads to.")
    root = tk.Tk()
    root.withdraw()
    downloads_folder = filedialog.askdirectory(title='Select Downloads Folder')
    print(f"Downloads will be saved to {downloads_folder}")
    my_password = hashlib.sha256(my_password.encode()).digest()
    my_cipher = AES.new(my_password, AES.MODE_EAX)
    def renew_cipher(nonce=None):
        global my_cipher
        if nonce is not None:
            my_cipher = AES.new(my_password, AES.MODE_EAX, nonce)
            return
        my_cipher = AES.new(my_password, AES.MODE_EAX)

    first_run = True
    while True:
        if first_run:
            request = 'upd'
            first_run = False
        else:
            print("Request input: upl, dnl, upd, end")
            request = str(input())
        while request not in ['upl', 'dnl', 'upd', 'end']:
            print("Request not match 'upl', 'dnl', 'upd', 'end'")
            request = str(input())
        match(request):
            case "upl":
                server.send(encrypt_with_padding(b'Upload', session_cipher))
                increment_nonce()
                file_path = filedialog.askopenfilename()
                filename = file_path[(file_path.rindex("/") + 1):]
                with open(file_path, 'rb') as file:
                    data = file.read()
                increment_nonce()
                increment_nonce()
                data_nonce = base64.b32encode(my_cipher.nonce)
                cipher_data = session_cipher.encrypt(my_cipher.encrypt(data))
                print(f'encrypting....\nclient nonce: {my_cipher.nonce}\nsession nonce:{session_cipher.nonce}')
                renew_cipher()
                decrement_nonce()
                decrement_nonce()
                data_size = sys.getsizeof(cipher_data)
                filename_nonce = base64.b32encode(my_cipher.nonce)
                cipher_filename = base64.b32encode(my_cipher.encrypt(filename.encode()))
                renew_cipher()

                leading_message = encrypt_with_padding(cipher_filename+b'|'+filename_nonce+b'|'+data_nonce+b'|'+str(data_size).encode(), session_cipher)
                server.send(leading_message)
                # nonce 3 is already used up so increment twice
                increment_nonce()
                increment_nonce()

                size_i = data_size // 1024
                size_r = data_size % 1024
                # this used nonce 3
                server.send(cipher_data)
                # the weird use of nonce increment and decrement is so the server can use nonces sequentially
                print("upload end", nonce_int)
                
            case "dnl":
                file_to_download = input("Choose file: ")
                while file_to_download not in filenames:
                    print(f'File "{file_to_download}" does not exist')
                    print(f'Choose file from:\n{filenames}')
                    file_to_download = input("Choose file: ")
                file_to_download_b32 = filename_b32_list[filenames.index(file_to_download)].encode()

                server.send(encrypt_with_padding(b'Download', session_cipher))
                increment_nonce()
                server.send(encrypt_with_padding(file_to_download_b32, session_cipher))
                increment_nonce()
                print("im here", nonce_int)
                data_size, data_nonce_b32 = decrypt_with_padding(server.recv(1024), session_cipher).decode().split("|")
                print(data_nonce_b32)
                data_size = int(data_size)
                data_nonce = base64.b32decode(data_nonce_b32)
                print(data_nonce)
                increment_nonce()
                data_ciphered = session_cipher.decrypt(server.recv(data_size))
                print(f'decrypting...\nsession nonce {session_cipher.nonce}')
                with open(f'{downloads_folder}/{file_to_download}.test', 'wb') as f:
                    f.write(data_ciphered)
                increment_nonce()
                renew_cipher(data_nonce)
                file_data = my_cipher.decrypt(data_ciphered)
                print(f'client nonce: {my_cipher.nonce}')
                renew_cipher()
                with open(f'{downloads_folder}/{file_to_download}', 'wb') as f:
                    f.write(file_data)
            case "upd":
                server.send(encrypt_with_padding(b'Update', session_cipher))
                increment_nonce()
                update_size = int(decrypt_with_padding(server.recv(1024), session_cipher).decode())
                increment_nonce()
                update_data = decrypt_with_padding(server.recv(update_size), session_cipher).decode()
                increment_nonce()
                update_dict = json.loads(update_data)
                
                filenames = []
                filename_b32_list = []
                for item in update_dict:
                    filename_b32_list.append(item)
                    filename_bytes = base64.b32decode(item)
                    filename_nonce_bytes = base64.b32decode(update_dict[item])
                    renew_cipher(filename_nonce_bytes)
                    filenames.append(my_cipher.decrypt(filename_bytes).decode())
                print(f"Files Availabe:\n{filenames}")
                renew_cipher()
                    

            case "end":
                server.send(encrypt_with_padding(b'End', session_cipher))
                increment_nonce()
                server.close()


    

    

