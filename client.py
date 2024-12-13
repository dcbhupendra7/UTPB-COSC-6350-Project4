import socket
import os
import logging
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac
import hashlib
import base64

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Client")

# Set up client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 9999))
logger.info("Connected to AP")

# Step 1: Generate client's private key and public key
client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()
client_public_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Receive server's public key
server_public_bytes = client.recv(1024)
server_public_key = serialization.load_pem_public_key(server_public_bytes)

# Send client's public key to the server
client.sendall(client_public_bytes)
logger.info("Client public key sent to server.")

# Generate shared key
shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
logger.info("Shared key established.")

# Step 2: Receive ANonce from server
anonce = client.recv(32)
logger.info(f"Received ANonce: {base64.b64encode(anonce).decode()}")

# Step 3: Generate SNonce and send to server
snonce = os.urandom(32)
client.sendall(snonce)
logger.info(f"Sent SNonce: {base64.b64encode(snonce).decode()}")

# Derive Pairwise Transient Key (PTK)
ptk = HKDF(
    algorithm=hashes.SHA256(),
    length=64,
    salt=anonce + snonce + b'unique_salt',
    info=b'wpa3-four-way-handshake'
).derive(shared_key)

# Step 4: Receive MIC from server and verify
mic_key = ptk[:32]
message = b"Message Integrity Check"
server_mic = client.recv(64)
logger.info(f"MIC Key (hex): {mic_key.hex()}")
computed_mic = hmac.new(mic_key, message, hashlib.sha256).digest()
logger.info(f"Computed MIC (hex): {computed_mic.hex()}")

# Send MIC confirmation back to server
client.sendall(computed_mic)
if hmac.compare_digest(server_mic, computed_mic):
    logger.info("MIC verified successfully. Handshake complete.")
else:
    logger.error("MIC verification failed. Handshake aborted.")
    client.close()
    exit()

# Receive and decrypt multiple messages from the server
while True:
    # First, read the 4-byte length prefix
    packet_length_data = client.recv(4)
    if not packet_length_data:
        break
    packet_length = struct.unpack('>I', packet_length_data)[0]

    # Then, read the exact length of the packet
    packet = client.recv(packet_length)
    if not packet:
        break

    # Extract nonce and ciphertext
    nonce = packet[:16]
    ciphertext = packet[16:]

    # Decrypt the ciphertext
    aes_key = ptk[32:64]
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(nonce))
    decryptor = aes_cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Decode message or handle non-UTF-8 data
    try:
        decoded_message = plaintext.decode('utf-8')
    except UnicodeDecodeError:
        decoded_message = "[Non-UTF-8 data received]"
    logger.info(f"Received encrypted packet: {base64.b64encode(packet).decode()}")
    logger.info(f"Decrypted message: {decoded_message}")

client.close()
