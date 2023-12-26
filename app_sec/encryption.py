from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def aes_encrypt(message, key):
    # Generate a random 16-byte Initialization Vector
    iv = os.urandom(16)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Encrypt the plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    # Get the Initialization Vector from the ciphertext
    iv = ciphertext[:16]

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message.decode()

def generate_key():
    return os.urandom(32)

def store_key(key, name):
    os.environ[name] = key.hex()
    # make it persistent
    with open('.env', 'a') as f:
        f.write(f'{name}={key.hex()}\n')

def get_key(name):
    if name in os.environ:
        return bytes.fromhex(os.environ[name])
    else:
        # read from .env file
        with open('.env', 'r') as f:
            for line in f:
                if line.startswith(name):
                    return bytes.fromhex(line.split('=')[1])