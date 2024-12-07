import socket
import threading
import os
import pyotp
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utility import recv_message, send_message, flush_socket

# RSA key pair generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Store OTP secrets and used OTPs for each client
client_otp_secrets = {}
used_otps = {}

def generate_client_otp():
    """Generate a unique OTP secret for a new client."""
    return pyotp.random_base32()

def recv_with_length_prefix(conn):
    data_length = int.from_bytes(conn.recv(4), byteorder='big')
    data = conn.recv(data_length)
    return data

def receive_file_data(conn):
    """Helper to receive file parts."""
    try:
        iv_type, iv_payload = recv_message(conn)
        encrypted_data_type, encrypted_data_payload = recv_message(conn)
        file_hash_type, file_hash_payload = recv_message(conn)
        salt_type, salt_payload = recv_message(conn)

        if not all([iv_type == "IV", encrypted_data_type == "ENCRYPTED_FILE",
                    file_hash_type == "HASH", salt_type == "SALT"]):
            raise ValueError("Incomplete file data received")

        return iv_payload, encrypted_data_payload, file_hash_payload, salt_payload
    except Exception as e:
        print(f"Error receiving file data: {e}")
        raise

def handle_client(conn):
    try:
        global client_otp_secrets, used_otps

        # Generate and store a unique OTP secret for this client
        client_otp_secret = generate_client_otp()
        client_totp = pyotp.TOTP(client_otp_secret)
        client_otp_secrets[conn] = client_totp
        used_otps[conn] = set()

        print(f"OTP Secret for client: {client_otp_secret}")

        # Step 1: Send public RSA key
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(public_key_bytes)

        # Step 2: Receive OTP and verify
        client_otp = conn.recv(6).decode()
        print(f"Received OTP: {client_otp}")

        if client_otp in used_otps[conn]:
            send_message(conn, "ERROR", "OTP already used (replay attack detected)")
            return

        if not client_totp.verify(client_otp):
            send_message(conn, "ERROR", "Invalid OTP")
            return

        used_otps[conn].add(client_otp)
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
            if not message_type:
                print("Client disconnected or connection error.")
                break

            print(f"Message Type: {message_type}, Payload: {payload}")

            if message_type == "SEND_FILE":
                try:
                    iv, encrypted_data, received_hash, salt = receive_file_data(conn)
                    file_name = payload.get("file_name", "unknown_file")
                    print(f"Receiving file: {file_name}")

                    hasher = hashes.Hash(hashes.SHA256())
                    hasher.update(bytes.fromhex(encrypted_data) + bytes.fromhex(salt))
                    calculated_hash = hasher.finalize()

                    if calculated_hash != bytes.fromhex(received_hash):
                        send_message(conn, "ERROR", "File integrity check failed")
                    else:
                        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(bytes.fromhex(iv)))
                        decryptor = cipher.decryptor()
                        plaintext = decryptor.update(bytes.fromhex(encrypted_data)) + decryptor.finalize()

                        file_name_only, file_extension = os.path.splitext(file_name)
                        formatted_file_name = f"received_{file_name_only}{file_extension}"

                        with open(formatted_file_name, "wb") as f:
                            f.write(plaintext)
                        send_message(conn, "STATUS", "File received and decrypted")
                        flush_socket(conn)
                except Exception as e:
                    print(f"Error in SEND_FILE: {e}")
                    send_message(conn, "ERROR", str(e))

            elif message_type == "REQUEST_FILE":
                try:
                    file_name = payload
                    if not os.path.exists(file_name):
                        send_message(conn, "ERROR", "File not found")
                        continue

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
                    flush_socket(conn)
                except Exception as e:
                    print(f"Error in REQUEST_FILE: {e}")
                    send_message(conn, "ERROR", str(e))

            elif message_type == "EXIT":
                send_message(conn, "STATUS", "Connection closed")
                print("Client requested termination.")
                break

    except Exception as e:
        print(f"Error in handle_client: {e}")
    finally:
        print("Closing connection.")
        conn.close()
        del client_otp_secrets[conn]
        del used_otps[conn]

# Server setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(5)
print("Server listening...")

while True:
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")
    threading.Thread(target=handle_client, args=(conn,)).start()
