from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_data(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-GCM.
    Returns: [IV(16 bytes) | TAG(16 bytes) | Ciphertext]
    """
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv + tag + ciphertext

def decrypt_data(key: bytes, data: bytes) -> bytes:
    """
    Decrypts data from the format [IV(16) | TAG(16) | Ciphertext].
    """
    iv = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)
