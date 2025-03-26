# -*- coding: utf-8 -*-
"""
Created on Tue March  26 08:345:47 2025

@author: IAN CARTER KULANI

"""


import socket
import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Function to load the server's public key
def load_public_key():
    with open('public_key.pem', 'rb') as public_file:
        public_key = serialization.load_pem_public_key(public_file.read(), backend=default_backend())
    return public_key

# Function to encrypt the message using the public key
def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Function to handle the process of sending the message from the GUI
def send_message():
    # Get user inputs from the GUI
    server_ip = server_ip_entry.get()
    server_port = int(server_port_entry.get())
    message = message_entry.get()

    # Load server's public key
    public_key = load_public_key()

    # Encrypt the message using the server's public key
    encrypted_message = encrypt_message(public_key, message)

    # Create and connect the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, server_port))

        # Send the encrypted message
        client_socket.send(encrypted_message)
        print(f"Encrypted message sent to server.")

        # Receive the server's response
        response = client_socket.recv(1024)
        response_label.config(text=f"Response from server: {response.decode()}")
    except Exception as e:
        response_label.config(text=f"Error: {str(e)}")
    finally:
        # Close the connection
        client_socket.close()

# GUI Class using Tkinter
class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Asymmetric Encryption Client")

        # Server IP Entry
        self.server_ip_label = tk.Label(self.root, text="Server IP:")
        self.server_ip_label.pack()

        self.server_ip_entry = tk.Entry(self.root)
        self.server_ip_entry.insert(0, "127.0.0.1")  # Default IP
        self.server_ip_entry.pack()

        # Server Port Entry
        self.server_port_label = tk.Label(self.root, text="Server Port:")
        self.server_port_label.pack()

        self.server_port_entry = tk.Entry(self.root)
        self.server_port_entry.insert(0, "65432")  # Default Port
        self.server_port_entry.pack()

        # Message Entry
        self.message_label = tk.Label(self.root, text="Message to Encrypt:")
        self.message_label.pack()

        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.pack()

        # Send Message Button
        self.send_button = tk.Button(self.root, text="Send Encrypted Message", command=send_message)
        self.send_button.pack()

        # Response Display
        self.response_label = tk.Label(self.root, text="Response from server will appear here.")
        self.response_label.pack()

# Main function to start the GUI application
def main():
    root = tk.Tk()
    gui = ClientGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
