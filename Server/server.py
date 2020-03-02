"""
    server.py - host an SSL server that checks passwords
    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)
    Put your team members' names:
    Sam Goulding
    Alex Palo
"""

import socket
import os
import pickle
import hashlib, uuid

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    #Get private key from directory file
    private_key = RSA.import_key(open("private_key.pem").read())
    #create cipher using public key
    cipher = PKCS1_OAEP.new(private_key)
    #encrypt session key with cipher
    session_key_decrypted = cipher.decrypt(session_key)
    #return
    return session_key_decrypted
    


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    #create cipher using session key
    cipher = AES.new(session_key,AES.MODE_EAX)
    nonce = cipher.nonce
    #encrypt message using cipher
    message = message.encode('utf-8')
    message_encrypted, tag = cipher.encrypt_and_digest(message)
    #return
    return message_encrypted, nonce
    


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key, nonce):
    #create cipher using session_key
    cipher = AES.new(session_key,AES.MODE_EAX,nonce)
    decrypted_message = cipher.decrypt(message)
    decrypted_message = decrypted_message.decode('utf-8')
    #return
    return decrypted_message


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # TODO: Generate the hashed password
                salt = line[1]
                hashed_password = hashlib.sha512(password.encode('utf-8') + salt.encode('utf-8')).hexdigest()
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                session_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                pickled = receive_message(connection)
                
                mes_nonce = pickle.loads(pickled)

                # TODO: Decrypt message from client
                decrypted_message = decrypt_message(mes_nonce[0],session_key,mes_nonce[1])
                
                # TODO: Split response from user into the username and password
                split_message = decrypted_message.split()
                user = split_message[0]
                password = split_message[1]
                
                # TODO: Encrypt response to client
                verify = verify_hash(user,password)
                if(verify):
                    plaintext_response = "User successfully authenticated!"
                else:
                    plaintext_response = "Password or username incorrect!"
                #encrypt response
                ciphertext_response, nonce = encrypt_message(plaintext_response,session_key)
                mes_nonce = [ciphertext_response,nonce]
                pickled = pickle.dumps(mes_nonce)

                # Send encrypted response
                send_message(connection, pickled)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()