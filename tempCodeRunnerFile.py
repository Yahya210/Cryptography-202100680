import socket
import threading
import os
import pyotp
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utility import recv_message, send_message


# OTP setup
otp_secret = pyotp.random_base32()
print("Server OTP Secret (for testing purposes):", otp_secret)
totp = pyotp.TOTP(otp_secret)

# RSA key pair generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Helper function to receive data with length prefix
def recv_with_length_prefix(conn):
    data_length = int.from_bytes(conn.recv(4), byteorder='big')
    data = conn.recv(data_length)
    return data

def receive_file_data(conn):
    """Helper to receive file parts."""
    iv = recv_message(conn)[1]
    encrypted_data = recv_message(conn)[1]
    received_hash = recv_message(conn)[1]
    salt = recv_message(conn)[1]
    return iv, encrypted_data, received_hash, salt

def handle_client(conn):
    try:
        # Step 1: Send public RSA key
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(public_key_bytes)

        # Step 2: Receive OTP and verify
        client_otp = conn.recv(6).decode()
        print(f"Received OTP: {client_otp}")
        if not totp.verify(client_otp):
            send_message(conn, "ERROR", "Invalid OTP")
            conn.close()
            return

        send_message(conn, "STATUS", "OTP verified")

        # Step 3: Receive encrypted AES key
        encrypted_aes_key_length = int.from_bytes(conn.recv(4), byteorder='big')
        encrypted_aes_key = conn.recv(encrypted_aes_key_length)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Communication loop
        while True:
            message_type, payload = recv_message(conn)
            if message_type is None:
                print("Client disconnected or connection error.")
                break

            print(f"Message Type: {message_type}, Payload: {payload}")

            if message_type == "SEND_FILE":
                iv, encrypted_data, received_hash, salt = receive_file_data(conn)

                file_name = payload.get("file_name", "unknown_file")
                print(f"Receiving file: {file_name}")

                # Verify file integrity
                hasher = hashes.Hash(hashes.SHA256())
                hasher.update(bytes.fromhex(encrypted_data) + bytes.fromhex(salt))
                calculated_hash = hasher.finalize()
                if calculated_hash != bytes.fromhex(received_hash):
                    send_message(conn, "ERROR", "File integrity check failed")
                else:
                    # Decrypt and save the file
                    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(bytes.fromhex(iv)))
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(bytes.fromhex(encrypted_data)) + decryptor.finalize()

                    file_name_only, file_extension = os.path.splitext(file_name)
                    formatted_file_name = f"received_{file_name_only}{file_extension}"

                    with open(formatted_file_name, "wb") as f:
                        f.write(plaintext)
                    send_message(conn, "STATUS", "File received and decrypted")

            elif message_type == "REQUEST_FILE":
                file_name = payload
                if not os.path.exists(file_name):
                    send_message(conn, "ERROR", "File not found")
                else:
                    with open(file_name, "rb") as f:
                        file_data = f.read()
                    iv = os.urandom(16)
                    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
                    encryptor = cipher.encryptor()
                    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

                    salt = os.urandom(16)
                    hasher = hashes.Hash(hashes.SHA256())
                    hasher.update(encrypted_data + salt)
                    file_hash = hasher.finalize()

                    send_message(conn, "IV", iv.hex())
                    send_message(conn, "ENCRYPTED_FILE", encrypted_data.hex())
                    send_message(conn, "HASH", file_hash.hex())
                    send_message(conn, "SALT", salt.hex())
                    send_message(conn, "STATUS", "File sent successfully")

            elif message_type == "EXIT":
                send_message(conn, "STATUS", "Connection closed")
                print("Client requested termination.")
                break

    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("Closing connection.")
        conn.close()


# Server setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(5)
print("Server listening...")

while True:
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")
    threading.Thread(target=handle_client, args=(conn,)).start()
