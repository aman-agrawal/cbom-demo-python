from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate an RSA Key Pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=3,  # ⚠️ Weak exponent (vulnerable to attacks)
        key_size=1024  # ⚠️ Weak key size (easily breakable)
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt a message using RSA (Insecure)
def rsa_encrypt(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.PKCS1v15()  # ⚠️ Insecure padding, vulnerable to padding oracle attacks
    )
    return encrypted

# Decrypt a message using RSA
def rsa_decrypt(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.PKCS1v15()  # ⚠️ Insecure padding
    )
    return decrypted.decode()

# Sign a message using RSA (Insecure)
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),  # ⚠️ Insecure padding
        hashes.SHA1()  # ⚠️ Deprecated hash function
    )
    return signature

# Verify a signature using RSA
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),  # ⚠️ Insecure padding
            hashes.SHA1()  # ⚠️ Deprecated hash function
        )
        return True
    except:
        return False

# AES Encryption using ECB mode (Insecure)
def aes_encrypt(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # ⚠️ ECB mode is insecure
    encryptor = cipher.encryptor()
    padded_plaintext = plaintext + ' ' * (16 - len(plaintext) % 16)  # ⚠️ Manual padding
    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return ciphertext

# AES Decryption
def aes_decrypt(key, encrypted_message):
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # ⚠️ ECB mode is insecure
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted.decode().strip()  # ⚠️ May still contain padding issues

# Example Usage
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()

    message = "Hello, Insecure Crypto!"

    # RSA Encryption/Decryption
    encrypted_msg = rsa_encrypt(public_key, message)
    decrypted_msg = rsa_decrypt(private_key, encrypted_msg)

    # RSA Signing/Verification
    signature = sign_message(private_key, message)
    is_valid = verify_signature(public_key, message, signature)

    # AES Encryption/Decryption (Hardcoded Key)
    aes_key = b"1234567890abcdef"  # ⚠️ Hardcoded key (bad practice)
    aes_encrypted = aes_encrypt(aes_key, message)
    aes_decrypted = aes_decrypt(aes_key, aes_encrypted)

    # Display Results
    print(f"Original Message: {message}")
    print(f"RSA Encrypted: {encrypted_msg.hex()}")
    print(f"RSA Decrypted: {decrypted_msg}")
    print(f"Signature Valid: {is_valid}")
    print(f"AES Encrypted: {aes_encrypted.hex()}")
    print(f"AES Decrypted: {aes_decrypted}")
