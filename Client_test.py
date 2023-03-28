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
# Event codes to send to server
# UPD : upload
# DLD : download
# FIN : upload or download finished
# END : end connection to server


def upload_file(server: socket.socket, filename: str):
    # Get the filesize of the file
    filesize = os.stat(filename).st_size
    # If open(filename, "type").read(bytesize) doesn't get the same number of bytes
    # it just hangs there waiting
    # Solution: calculate how many times we send 4096 bytes then send the remainder
    # the server will do the same on it's end
    size_a = filesize // 4096
    size_r = filesize % 4096

    name_from_path = ""
    for i in range(len(filename) - 1, -1, -1):
        if filename[i] == "\\":
            break
        else:
            name_from_path += filename[i]
    name_from_path = name_from_path[::-1]

    # Save the filename, file size, number of 4096 bytes, and remainder
    format_filename = f"{name_from_path}|{filesize}|{size_a}|{size_r}"
    filename_size = sys.getsizeof(format_filename.encode())
    # After sending acknowledgement, server expects a byte size of 4096 bytes
    # Make the filename 4096 bytes
    if filename_size < 4096:
        for i in range(4096 - filename_size):
            format_filename += " "
    # Send the filename, file size, number of 4096 bytes, and remainder to the server
    server.send(format_filename.encode())

    # Send the file
    with open(filename, "rb") as f:
        for i in range(size_a):
            bytes_read = f.read(4096)
            server.sendall(bytes_read)
        bytes_read = f.read(size_r)
        server.sendall(bytes_read)
        print("File sent")

    # The server is supposed to send "File {filename} {bytesize} bytes received"
    print(server.recv(4096).decode().strip())


def download_file(server, filename: str, destination: str):
    pass


# C:\Users\4225482\Documents\python.py
def encrypt_file(key, file_path):
    filename = file_path[file_path.rfind("\\")+1:]
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipher_filename, tag = cipher.encrypt(filename.encode())

    with open(file_path, "rb") as binary_file:
        cipher_file = cipher.encrypt(binary_file.read())

    return nonce, cipher_filename, cipher_file

def decrypt_file(key, nonce, cipher_filename, cipher_file=None):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    filename = cipher.decrypt(cipher_filename)
    if cipher_file == None:
        return filename

if __name__ == '__main__':
    host = input("Host ip: ")
    port = int(input("Host Port: "))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((host, port))

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
        return session_cipher.decrypt(base64.b32decode(data.decode().strip().encode()))

    
    password = str(input("Password: "))
    server.send(encrypt_with_padding(password.encode(), session_cipher))
    increment_nonce()

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
                renew_cipher()
                # return to nonce 1
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
                data_size = int(data_size)
                data_nonce = base64.b32decode(data_nonce_b32)
                increment_nonce()
                data_ciphered = session_cipher.decrypt(server.recv(data_size))
                increment_nonce()
                renew_cipher(data_nonce)
                file_data = my_cipher.decrypt(data_ciphered)
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
                pass

    

    

