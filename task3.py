from ctypes.wintypes import WORD
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os  # For generating random IV

def derive_key(password, salt=b'salt', iterations=100000):
    password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Use a 256-bit key for AES-256
        salt=salt,
        iterations=iterations
    )
    key = kdf.derive(password)
    return key

def encrypt_text(plaintext, password):
    key = derive_key(password)
    
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)  # 16 bytes for AES block size
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    
    encrypted_text = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + encrypted_text  # Prepend IV to ciphertext

def decrypt_text(ciphertext, password):
    key = derive_key(password)
    
    # Extract IV from the beginning of ciphertext
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    decrypted_padded_text = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_plaintext = unpadder.update(decrypted_padded_text) + unpadder.finalize()
    
    return unpadded_plaintext.decode()


plaintext = input("Type your WORD:")
password = input('Type your password:')

encrypted_text = encrypt_text(plaintext, password)
print("Encrypted Text:", encrypted_text)

password = input('Type your password:')

decrypted_text = decrypt_text(encrypted_text, password)
print("Decrypted Text:", decrypted_text)
