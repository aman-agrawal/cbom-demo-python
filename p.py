from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate an RSA Key Pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt a message using RSA
def rsa_encrypt(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Decrypt a message using RSA
def rsa_decrypt(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Sign a message using RSA
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify a signature using RSA
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# AES Encryption
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_plaintext = plaintext + ' ' * (16 - len(plaintext) % 16)  # Padding
    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext  # Store IV with ciphertext

# AES Decryption
def aes_decrypt(key, encrypted_message):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted.decode().strip()  # Remove padding

# Example Usage
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()

    message = "Hello, Cryptography!"

    # RSA Encryption/Decryption
    encrypted_msg = rsa_encrypt(public_key, message)
    decrypted_msg = rsa_decrypt(private_key, encrypted_msg)

    # RSA Signing/Verification
    signature = sign_message(private_key, message)
    is_valid = verify_signature(public_key, message, signature)

    # AES Encryption/Decryption
    aes_key = os.urandom(32)  # 256-bit key
    aes_encrypted = aes_encrypt(aes_key, message)
    aes_decrypted = aes_decrypt(aes_key, aes_encrypted)

    # Display Results
    print(f"Original Message: {message}")
    print(f"RSA Encrypted: {encrypted_msg.hex()}")
    print(f"RSA Decrypted: {decrypted_msg}")
    print(f"Signature Valid: {is_valid}")
    print(f"AES Encrypted: {aes_encrypted.hex()}")
    print(f"AES Decrypted: {aes_decrypted}")
