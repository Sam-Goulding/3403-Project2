"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Sam Goulding
    Alex Palo


"""

import socket
import os
import pickle

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
def pad_message(message):
    return message + " "*((16-len(message))%16)


def generate_key():
    AES_key = os.urandom(16)
    return AES_key


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    #Get public key from directory file
    public_key = RSA.import_key(open("public_key.pem").read())
    #create cipher using public key
    cipher = PKCS1_OAEP.new(public_key)
    #encrypt session key with cipher
    session_key_encrypted = cipher.encrypt(session_key)
    #return
    return session_key_encrypted
    
    


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

# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        encrypted_message, nonce = encrypt_message(message,key)
        mes_nonce = [encrypted_message,nonce]
        pickled = pickle.dumps(mes_nonce)
        
        send_message(sock,pickled)

        # TODO: Receive and decrypt response from server
        pickled = receive_message(sock)
        mes_nonce = pickle.loads(pickled)

        decrypted_message = decrypt_message(mes_nonce[0],key,mes_nonce[1])
        #print message from server
        print(decrypted_message)
        
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
