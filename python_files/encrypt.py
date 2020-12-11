#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from socket import socket, AF_INET,SOCK_STREAM
import ipfshttpclient



#Initialize key and IV values
key_hex_string = '00112233445566778899AABBCCDDEEFF'
iv_hex_string  = '000102030405060708090A0B0C0D0E0F'

key_message = bytes.fromhex(key_hex_string)
iv  = bytes.fromhex(iv_hex_string)

#Initialize TCP Server
serverPort = 13000
serverSocket = socket(AF_INET,SOCK_STREAM)
serverSocket.bind(('',serverPort))
serverSocket.listen(1)
print('The server is ready to receive')

while True:
    # Listen for public key
    connectionSocket, addr = serverSocket.accept()
    publicKey = RSA.importKey(connectionSocket.recv(3000))
    print(addr)
    
    # Read File
    message = None
    with open("" + input("Enter filename, include file extension: "), "rb") as File:
        message = File.read()


    # Encrypt and send secret key 
    cipherRSA = PKCS1_OAEP.new(publicKey)                  
    ciphertextRSA = cipherRSA.encrypt(key_message)
    connectionSocket.send(ciphertextRSA) 

    # Encrypt file
    cipherCBC = AES.new(key_message, AES.MODE_CBC, iv)                   
    ciphertextCBC = cipherCBC.encrypt(Padding.pad(message, 16))       

    # Write encrypted file
    with open("encrypted_file", "wb") as File:
        File.write(ciphertextCBC)

    # Add encrypted file to IPFS
    with ipfshttpclient.connect() as client:
        hash = client.add("encrypted_file")['Hash']
        print("Save this CID to retrieve it: " + hash)

    # Send hash to Client
    connectionSocket.send(hash.encode()) 
    
    # Close Connection
    connectionSocket.close()

