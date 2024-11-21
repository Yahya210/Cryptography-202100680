import socket
import os
import pyotp
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utility import recv_message, send_message

# OTP setup
otp_secret = input("Enter the OTP secret (same as server's for testing): ")
totp = pyotp.TOTP(otp_secret)

# Generate AES key
aes_key = os.urandom(32)

# Client setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))

# Step 1: Receive public RSA key
server_public_key_bytes = client_socket.recv(1024)
server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

# Step 2: Send OTP
otp = totp.now()
print(f"Sending OTP: {otp}")
client_socket.sendall(otp.encode())

# Step 3: Encrypt AES key and send
encrypted_aes_key = server_public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Send length of AES key first
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
        with open(file_path, "rb") as f:
            file_data = f.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
        salt = os.urandom(16)
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(encrypted_data + salt)
        file_hash = hasher.finalize()
        send_message(client_socket, "SEND_FILE", {"file_name": os.path.basename(file_path)})
        send_message(client_socket, "IV", iv.hex())
        send_message(client_socket, "ENCRYPTED_FILE", encrypted_data.hex())
        send_message(client_socket, "HASH", file_hash.hex())
        send_message(client_socket, "SALT", salt.hex())
    elif command == "REQUEST_FILE":
        file_name = input("Enter the file name to request: ").strip()
        send_message(client_socket, "REQUEST_FILE", file_name)

        # Wait for the server response
        status = recv_message(client_socket)
        if status[0] == "ERROR":
            print(f"Error: {status[1]}")
        else:
            # Receive the IV, encrypted data, salt, and hash
            iv = recv_message(client_socket)[1]
            encrypted_data = recv_message(client_socket)[1]
            file_hash = recv_message(client_socket)[1]
            salt = recv_message(client_socket)[1]

            # Decrypt file (using the AES key)
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(bytes.fromhex(iv)))
            decryptor = cipher.decryptor()
            file_data = decryptor.update(bytes.fromhex(encrypted_data)) + decryptor.finalize()

            # Step 5: Save the file with the naming format
            file_name_only, file_extension = os.path.splitext(file_name)
            formatted_file_name = f"received_{file_name_only}{file_extension}"

            
            with open(formatted_file_name, "wb") as f:
                f.write(file_data)
                print(f"File {formatted_file_name} received and decrypted successfully.")

    elif command == "EXIT":
        send_message(client_socket, "EXIT", "")
        break

client_socket.close()
