import socket
import os
import pyotp
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utility import recv_message, send_message, flush_socket

# Client setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))

# Step 1: Receive public RSA key from the server
server_public_key_bytes = client_socket.recv(1024)
server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

# Step 2: Generate OTP based on the secret received from the server
otp_secret = input("Enter OTP secret (provided by server for testing): ")
totp = pyotp.TOTP(otp_secret)

# Send OTP to the server
otp = totp.now()
print(f"Sending OTP: {otp}")
client_socket.sendall(otp.encode())

# Step 3: Generate AES key for file encryption
aes_key = os.urandom(32)

# Encrypt AES key using the server's public RSA key
encrypted_aes_key = server_public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Send the length of the encrypted AES key and the encrypted AES key itself
client_socket.sendall(len(encrypted_aes_key).to_bytes(4, byteorder='big'))
client_socket.sendall(encrypted_aes_key)

# Communication loop
while True:
    command = input("Enter command (SEND_FILE, REQUEST_FILE, EXIT): ").strip()
    if command == "SEND_FILE":
        file_path = input("Enter the file path to send: ").strip()
        if not os.path.exists(file_path):
            print("File not found.")
            continue

        # Encrypt the file to be sent
        with open(file_path, "rb") as f:
            file_data = f.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
        salt = os.urandom(16)
        
        # Compute the hash of the encrypted data for file integrity
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(encrypted_data + salt)
        file_hash = hasher.finalize()

        # Send the file details
        send_message(client_socket, "SEND_FILE", {"file_name": os.path.basename(file_path)})
        send_message(client_socket, "IV", iv.hex())
        send_message(client_socket, "ENCRYPTED_FILE", encrypted_data.hex())
        send_message(client_socket, "HASH", file_hash.hex())
        send_message(client_socket, "SALT", salt.hex())
        flush_socket(client_socket)

    elif command == "REQUEST_FILE":
        file_name = input("Enter the file name to request: ").strip()
        send_message(client_socket, "REQUEST_FILE", file_name)

        # Receive all parts of the file data
        iv_type, iv_payload = recv_message(client_socket)
        encrypted_data_type, encrypted_data_payload = recv_message(client_socket)
        file_hash_type, file_hash_payload = recv_message(client_socket)
        salt_type, salt_payload = recv_message(client_socket)
        
        if iv_type == "IV" and encrypted_data_type == "ENCRYPTED_FILE":
            iv = bytes.fromhex(iv_payload)
            encrypted_data = bytes.fromhex(encrypted_data_payload)
            salt = bytes.fromhex(salt_payload)

            # Decrypt the file
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            file_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Save the file
            file_name_only, file_extension = os.path.splitext(file_name)
            formatted_file_name = f"received_{file_name_only}{file_extension}"

            with open(formatted_file_name, "wb") as f:
                f.write(file_data)
            print(f"File {formatted_file_name} received and decrypted successfully.")
            flush_socket(client_socket)
        else:
            print("Error receiving file components. Please check the server.")
    
    elif command == "EXIT":
        send_message(client_socket, "EXIT", "")
        print("Exiting...")
        break

client_socket.close()
