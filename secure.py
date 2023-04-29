import socket
import threading
import os
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

salt = b"\xfcv\x101\x19k\xbe?'r;\xc3\x16\xe6\x7f\xbf\xbbiV\xae$\x94>\xb4H<A\x9f\xed}w\xca"
password = "password"

key = PBKDF2(hashlib.sha256(password.encode()).digest(), salt, dkLen=32)
#iv = b'\xd7]\xbc/\xc4\xb8X<l{\x94\xac\n/\x82J'
#print(key)
#message = b"Hello, World!"

#cipher = AES.new(key, AES.MODE_CBC)
#ciphered_data = cipher.encrypt(pad(message, AES.block_size))

#cipher = AES.new(key, AES.MODE_CBC, iv=iv)
#original = unpad(cipher.decrypt(ciphered_data), AES.block_size)
#print(original)

choice = input("Host (1) or Connect (2):")

if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 9999))
    server.listen()

    client, _ = server.accept()

elif choice == "2":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 9999))

else:
    exit()

def sending_messages(c):
    while True:
        sent_message = input("")
        sent_iv = get_random_bytes(16)
        cipher_sent = AES.new(key, AES.MODE_CBC, iv=sent_iv)
        sent_padded = pad(sent_message.encode(), AES.block_size)
        sent_cipher = cipher_sent.encrypt(sent_padded)
        c.send(sent_iv)
        c.send(sent_cipher)
        print(f"Encrypted: {sent_cipher}")
        if (sent_message == "exit"):
            os._exit(1)

def receiving_messages(c):
    while True:
        recv_iv = c.recv(16)
        recv_cipher = c.recv(1024)
        print(f"Ciphertext: {recv_cipher}")
        cipher_recv = AES.new(key, AES.MODE_CBC, iv=recv_iv)
        recv_padded = cipher_recv.decrypt(recv_cipher)
        recv_message = unpad(recv_padded, AES.block_size).decode()
        print("Plaintext: " + recv_message)
        if (recv_message == "exit"):
            os._exit(1)

threading.Thread(target=sending_messages, args=(client,)).start()
threading.Thread(target=receiving_messages, args=(client,)).start()