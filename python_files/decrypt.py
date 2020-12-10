#!/usr/bin/python3

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util import Padding
import ipfshttpclient
from socket import socket, AF_INET,SOCK_STREAM

serverName = '172.18.137.64'
serverPort = 13000

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName,serverPort))

#Send public key
publicKey = open('keys/public.pem', 'rb').read()
clientSocket.send(publicKey)

#Wait for Secret Key
ciphertextRSA = clientSocket.recv(1024)
secretKey = ciphertextRSA
print('From Server: ', ciphertextRSA) 

#Wait for Hash Value
hash = clientSocket.recv(1024)
print(hash)
hash = hash.decode("utf-8")
clientSocket.close()


prikey_pem = open('keys/private.pem').read()
prikey = RSA.importKey(prikey_pem, passphrase='dees')
cipherRSA = PKCS1_OAEP.new(prikey)

key = cipherRSA.decrypt(secretKey)
print(key)


iv_hex_string  = '000102030405060708090A0B0C0D0E0F'
iv  = bytes.fromhex(iv_hex_string)

ciphertextCBC = None

with open("encrypted_file", "rb") as File:
    ciphertextCBC = File.read()

with ipfshttpclient.connect() as client:
    # hash = input("Enter CID (hash) of content to decrypt:")
    client.get(hash,'./incoming_files')

with open('incoming_file/' + hash, 'rb') as File:
    ciphertextCBC = File.read()

# Decrypt the ciphertext
cipherCBC = AES.new(key, AES.MODE_CBC, iv)                 
plaintext = cipherCBC.decrypt(ciphertextCBC)                

with open("decrypted_file", "wb") as File:
    File.write(Padding.unpad(plaintext,16))

