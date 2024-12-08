import os
import base64
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime

# Function to read the key from the .key file
def getKey(key_location):
    with open(key_location, "rb") as keyfile:  # Open in binary mode
        return keyfile.read()

# Function to save encrypted data to a file
def save_to_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)
    print(f"Encrypted data saved to {file_path}")

# Function to read data from a file
def read_from_file(file_path):
    with open(file_path, "rb") as file:
        data = file.read()
        return data

# Function to encrypt text or data
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    return iv + ciphertext  # Return IV + ciphertext for decryption

# Function to decrypt ciphertext
def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]  # Extract the first 16 bytes as IV
    actual_ciphertext = ciphertext[16:]  # The rest is the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")

# Function to generate and save a key
def generate_and_save_key(key_file_path, key_length=32):
    key = os.urandom(key_length)  # Generate a random key of desired length
    with open(key_file_path, 'wb') as key_file:
        key_file.write(key)
    print(f"Key saved to {key_file_path}")

# Command-line argument parser
def parse_args():
    parser = argparse.ArgumentParser(description="Secure messaging tool with AES-256 encryption.")
    parser.add_argument("-k", "--key", required=True, help="Location of the key file (.key)")
    parser.add_argument("-e", "--encrypt", help="Message to encrypt", default=None)
    parser.add_argument("-d", "--decrypt", help="File to decrypt", default=None)
    parser.add_argument("-s", "--send", help="Send encrypted message via ncat (optional)", action="store_true")
    parser.add_argument("-l", "--listen", help="Listen for encrypted message via ncat (optional)", action="store_true")
    parser.add_argument("-f", "--file", help="File to save encrypted/decrypted message", default=None)
    parser.add_argument("-g", "--generate", help="Generate a key and save it", action="store_true")
    parser.add_argument("-m", "--message_only", help="Only encrypt message and save to file without ncat", action="store_true")

    return parser.parse_args()

# Main function to handle user interaction
def main():
    args = parse_args()
    
    # Load key
    if not os.path.exists(args.key):
        print(f"Key file {args.key} not found!")
        return
    key = getKey(args.key)
    
    # Key generation (only works when -g is passed)
    if args.generate:
        key_file = input("Enter the file path to save the generated key: ")
        key_length = int(input("Enter key length (32 for AES-256): "))
        generate_and_save_key(key_file, key_length)
        return
    
    # Encrypt or decrypt mode
    if args.message_only:
        # Encrypt and save without sending or listening
        if args.encrypt:
            plaintext = args.encrypt
            encrypted = aes_encrypt(key, plaintext)
            if args.file:
                save_to_file(args.file, encrypted)
            else:
                # Default file name
                filename = f"{datetime.now().strftime('%Y-%m-%d')}_message.encry"
                save_to_file(filename, encrypted)
            print(f"Message encrypted and saved to {filename}")
        else:
            print("No message provided to encrypt.")
        
    elif args.decrypt:
        encrypted = read_from_file(args.decrypt)
        decrypted = aes_decrypt(key, encrypted)
        print("Decrypted message:", decrypted)
        
    # For send/listen modes, you'll need the ncat functionality and port info (not implemented here)
    elif args.listen or args.send:
        print("ncat functionality can be implemented for sending and receiving encrypted messages.")

if __name__ == "__main__":
    main()
