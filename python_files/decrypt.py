#!/usr/bin/python3

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util import Padding

ciphertextRSA = open('python_files/ciphertext.bin', 'rb').read()

prikey_pem = open('python_files/private.pem').read()
prikey = RSA.importKey(prikey_pem, passphrase='dees')
cipherRSA = PKCS1_OAEP.new(prikey)
key = cipherRSA.decrypt(ciphertextRSA)
print(key)


iv_hex_string  = '000102030405060708090A0B0C0D0E0F'
iv  = bytes.fromhex(iv_hex_string)

ciphertextCBC = None
with open("python_files/e_message", "rb") as File:
    ciphertextCBC = File.read()

# Decrypt the ciphertext
cipherCBC = AES.new(key, AES.MODE_CBC, iv)                 
plaintext = cipherCBC.decrypt(ciphertextCBC)                

with open("python_files/decrypted_file", "wb") as File:
    File.write(plaintext)

