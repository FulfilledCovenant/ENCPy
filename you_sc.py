import base64

# Custom Encryption
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

# Hex Conversion
def hex_encrypt(text):
    return text.encode('utf-8').hex()

def hex_decrypt(text):
    return bytes.fromhex(text).decode('utf-8')

# Base64 Encoding
def base64_encrypt(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def base64_decrypt(text):
    return base64.b64decode(text).decode('utf-8')

# Unified Interface
def encrypt_text(text, method):
    if method == 'custom':
        return custom_encrypt(text)
    elif method == 'hex':
        return hex_encrypt(text)
    elif method == 'base64':
        return base64_encrypt(text)
    raise ValueError("Invalid encryption method")

def decrypt_text(text, method):
    if method == 'custom':
        return custom_decrypt(text)
    elif method == 'hex':
        return hex_decrypt(text)
    elif method == 'base64':
        return base64_decrypt(text)
    raise ValueError("Invalid decryption method")
