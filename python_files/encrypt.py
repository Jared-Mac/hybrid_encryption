#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

key_hex_string = '00112233445566778899AABBCCDDEEFF'
iv_hex_string  = '000102030405060708090A0B0C0D0E0F'

key_message = bytes.fromhex(key_hex_string)
iv  = bytes.fromhex(iv_hex_string)

key = RSA.importKey(open('python_files/public.pem').read()) 
cipherRSA = PKCS1_OAEP.new(key)                  
ciphertextRSA = cipherRSA.encrypt(key_message)
f = open('python_files/ciphertext.bin','wb')
f.write(ciphertextRSA)
f.close()


# Encrypt the entire data
message = None
with open("python_files/" + input("Enter filename, include file extension: "), "rb") as File:
    message = File.read()



cipherCBC = AES.new(key_message, AES.MODE_CBC, iv)                   
ciphertextCBC = cipherCBC.encrypt(Padding.pad(message, 16))       


with open("python_files/e_message", "wb") as File:
    File.write(ciphertextCBC)