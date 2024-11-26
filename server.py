import socket
import os
import hashlib
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac
import base64

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Server")

# Set up server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 9999))
server.listen(1)
logger.info("Server listening on port 9999...")

client_socket, client_address = server.accept()
logger.info(f"Connection established with {client_address}")

# Step 1: Generate server's private key and public key
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()
server_public_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Send server's public key to the client
client_socket.sendall(server_public_bytes)
logger.info("Server public key sent to client.")

# Receive client's public key
client_public_bytes = client_socket.recv(1024)
client_public_key = serialization.load_pem_public_key(client_public_bytes)
logger.info("Received client's public key.")

# Generate shared key
shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
logger.info("Shared key established.")
logger.info(f"Shared key (hex): {shared_key.hex()}")

# Step 2: Send ANonce to client
anonce = os.urandom(32)
client_socket.sendall(anonce)
logger.info(f"Sent ANonce: {base64.b64encode(anonce).decode()}")

# Step 3: Receive SNonce from client
snonce = client_socket.recv(32)
logger.info(f"Received SNonce: {base64.b64encode(snonce).decode()}")

# Derive Pairwise Transient Key (PTK)
ptk = HKDF(
    algorithm=hashes.SHA256(),
    length=64,
    salt=anonce + snonce + b'unique_salt',
    info=b'wpa3-four-way-handshake'
).derive(shared_key)

# Step 4: Generate MIC and send to client
mic_key = ptk[:32]
message = b"Message Integrity Check"
logger.info(f"MIC Key (hex): {mic_key.hex()}")
mic = hmac.new(mic_key, message, hashlib.sha256).digest()
logger.info(f"Generated MIC (hex): {mic.hex()}")
client_socket.sendall(mic)
logger.info(f"Sent MIC: {base64.b64encode(mic).decode()}")

# Step 5: Receive MIC confirmation from client
client_mic = client_socket.recv(64)
if hmac.compare_digest(mic, client_mic):
    logger.info("MIC verified successfully. Handshake complete.")
else:
    logger.error("MIC verification failed. Handshake aborted.")
    client_socket.close()
    server.close()
    exit()

# Encrypt and send multiple messages to the client
aes_key = ptk[32:64]
# nonce will be generated separately for each message

messages = [b'Hello, client!', b'Welcome to WPA3 simulation!', b'This is a secure message.']
for msg in messages:
    nonce = os.urandom(16)
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(nonce))
    encryptor = aes_cipher.encryptor()  # Generate a new nonce for each message
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(nonce))
    encryptor = aes_cipher.encryptor()
    ciphertext = nonce + encryptor.update(msg)
    client_socket.sendall(ciphertext)
    logger.info(f"Original message: {msg.decode()}")
    logger.info(f"Sent encrypted packet: {base64.b64encode(ciphertext).decode()}")

client_socket.close()
server.close()

