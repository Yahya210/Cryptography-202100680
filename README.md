# End-to-End Encrypted File Sharing System with OTP-based Authentication
Overview
This is a secure command-line file-sharing application built using Python. The system employs OTP-based authentication, RSA for key exchange, and AES for file encryption to ensure data confidentiality, integrity, and authenticity.

## Features
1. OTP-Based Authentication
Each client is assigned a unique OTP for authentication.
OTPs are time-sensitive and validated against the server using TOTP (Time-based One-Time Passwords).
Replay attacks are mitigated by tracking used OTPs.
2. End-to-End Encryption
RSA Encryption: Used for securely exchanging the AES key between the client and server.
AES Encryption: Used for encrypting and decrypting files during transmission.
SHA-256 Hashing: Ensures file integrity by comparing calculated hashes before and after transmission.
3. File Sharing
Securely send and request files.
Files are encrypted before transfer and decrypted upon receipt.
4. Replay Attack Prevention
Used OTPs are stored to prevent reuse.
OTP expiration ensures time-limited access.
## File Structure
<ul>
<li>server.py: The server-side implementation of the file-sharing system.</li>
<li>client.py: The client-side implementation of the file-sharing system.</li>
<li>utility.py: A helper module for sending and receiving structured messages between the client and server.</li>
</ul>

## Setup and Usage
1. Requirements
Ensure the following Python libraries are installed:

<ul>
<li>socket</li>
<li>threading</li>
<li>pyotp</li>
<li>cryptography</li>
</ul>

2. Running the Application
Step 1: Start the Server
Open a terminal and navigate to the server directory.
Run the server:
python server.py
The server will start listening on localhost:65432.
Step 2: Start the Client
Open a terminal and navigate to the client directory.
Run the client:
python client.py
Input the OTP secret provided by the server for authentication.
3. Using the System
### Client Commands
SEND_FILE: Securely upload a file to the server.
Input the file path when prompted.
REQUEST_FILE: Download a file from the server.
Input the file name when prompted.
EXIT: Disconnect from the server.
Server Functionality
Handles multiple client connections simultaneously.
Verifies OTPs and authenticates clients.
Encrypts and decrypts files for secure file sharing.
Security Features
OTP Authentication

Each client receives a unique OTP.
OTPs are time-limited and cannot be reused.
File Encryption

Files are encrypted using AES with a randomly generated key.
The AES key is securely exchanged using RSA.
Integrity Verification

Files are hashed using SHA-256 with a salt to ensure data integrity.


Replay Attack Prevention

Used OTPs are tracked to prevent duplication attacks.
Example Usage
Registration and Authentication
The server generates an OTP secret upon startup for each client, and has to authenticate:
Client Sends a file to the server

<img width="1075" alt="Screenshot 2024-12-04 at 10 27 37 AM" src="https://github.com/user-attachments/assets/6a07fc35-9a3c-4bac-a195-5684307434d0">

Client requests a file from the server:

<img width="1077" alt="Screenshot 2024-12-04 at 10 28 15 AM" src="https://github.com/user-attachments/assets/5dec3188-f3b8-4559-9250-d880e11ca2e3">

## List of Dependencies
### Python Libraries:
<ul>
<li>socket and threading: For networking and multithreading.</li>
<li>pyotp: For OTP generation and verification.</li>
<li>cryptography: For RSA and AES encryption, and SHA-256 hashing.</li>
</ul>

## Author
This End-to-End Encrypted File Sharing System was developed by **Yahya Mohamed** as a demonstration of secure file sharing using OTP-based authentication and advanced encryption techniques.
