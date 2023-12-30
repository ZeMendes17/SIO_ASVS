from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os

def chacha20_encrypt(message, key):
    iv = os.urandom(16)

    try:
        cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return iv + ciphertext
    except Exception as e:
        print("Encryption error:", e)
        return None

def chacha20_decrypt(ciphertext, key):
    iv = ciphertext[:16]

    try:
        cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        return plaintext.decode()
    except Exception as e:
        print("Decryption error:", e)
        return None

def generate_key():
    return os.urandom(32)

def store_key(key, name):
    os.environ[name] = key.hex()
    # if there is no .env file, create one
    if not os.path.exists('.env'):
        open('.env', 'w').close()
    # if the key is already in the .env file, remove it
    with open('.env', 'r') as f:
        lines = f.readlines()
    with open('.env', 'w') as f:
        for line in lines:
            if not line.startswith(name):
                f.write(line)

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