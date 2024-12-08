from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Function to generate a secure key and save it to a .key file
def generate_and_save_key(key_file_path, key_length=32):
    key = os.urandom(key_length)  # Generate a random key of desired length
    with open(key_file_path, 'wb') as key_file:
        key_file.write(key)
    print(f"Key saved to {key_file_path}")

# Function to load the key from a .key file
def load_key(key_file_path):
    with open(key_file_path, 'rb') as key_file:
        return key_file.read()

# Example usage
if __name__ == "__main__":
    key_file = ".key"

    # Generate and save key
    generate_and_save_key(key_file)

    # Load key
    key = load_key(key_file)