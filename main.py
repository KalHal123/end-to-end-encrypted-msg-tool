import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Function to read the key from the .key file
def getKey(key_location):
    with open(key_location, "rb") as keyfile:  # Open in binary mode
        return keyfile.read()
    
def save_to_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)
    print(f"Encrypted data saved to {file_path}")
    
def read_from_file(file_path):
    with open(file_path, "rb") as file:
        data = file.read()
        return(data)

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

# Example usage
if __name__ == "__main__":
    key_file = ".key"

    # Load the key
    if not os.path.exists(key_file):
        print(f"Key file {key_file} not found!")
    else:
        key = getKey(key_file)
        print("To encrypt a message type 1. To decrypt a message type 2.")
        enorde = input("> ")
        if enorde == "1":
            # Encrypt data
            plaintext = input("Message to encrypt: ")
            encrypted = aes_encrypt(key, plaintext)
            save_to_file("encrypted_message.encry", encrypted)
        if enorde == "2":
            # Decrypt data
            file_path = input("File to decrypt: ")
            encrypted = read_from_file(file_path)
            decrypted = aes_decrypt(key, encrypted)
            print("Decrypted data:", decrypted)
