import hashlib
import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Original custom encryption
def custom_encrypt(text):
    encrypted = ""
    for char in text.encode('utf-8'):
        encrypted += f"{char:03d}{char:02x}"
    return encrypted

def custom_decrypt(text):
    byte_values = []
    for i in range(0, len(text), 5):
        chunk = text[i:i+5]
        byte_values.append(int(chunk[:3]))
    return bytes(byte_values).decode('utf-8')

# Hex conversion
def hex_encrypt(text):
    return text.encode('utf-8').hex()

def hex_decrypt(text):
    return bytes.fromhex(text).decode('utf-8')

# Base64 encoding
def base64_encrypt(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def base64_decrypt(text):
    return base64.b64decode(text).decode('utf-8')

# SHA-256 (one-way hash)
def sha256_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

# AES Encryption (256-bit)
def aes_encrypt(text, key):
    key = key.encode('utf-8').ljust(32, b'\0')[:32]  # Ensure 32-byte key
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def aes_decrypt(text, key):
    key = key.encode('utf-8').ljust(32, b'\0')[:32]
    data = base64.b64decode(text)
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size).decode('utf-8')

# Unified interface
def encrypt_text(text, method):
    if method == 'custom':
        return custom_encrypt(text)
    elif method == 'hex':
        return hex_encrypt(text)
    elif method == 'base64':
        return base64_encrypt(text)
    elif method == 'sha256':
        return sha256_hash(text)
    elif method == 'aes':
        if not key:
            raise ValueError("AES requires an encryption key")
        return aes_encrypt(text, key)
    raise ValueError("Invalid encryption method")

def decrypt_text(text, method):
    if method == 'custom':
        return custom_decrypt(text)
    elif method == 'hex':
        return hex_decrypt(text)
    elif method == 'base64':
        return base64_decrypt(text)
    elif method == 'sha256':
        raise ValueError("SHA-256 cannot be decrypted")
    elif method == 'aes':
        if not key:
            raise ValueError("AES requires a decryption key")
        return aes_decrypt(text, key)
    raise ValueError("Invalid decryption method")
