import random

def encrypt_text(text):
    """
    Encrypts text by converting each byte to a fixed-length decimal and hex string.

    Args:
        text: The text to encrypt.

    Returns:
        The encrypted string.
    """

    bytecode = text.encode('utf-8')  # Convert to bytecode

    encrypted_string = ""
    for byte in bytecode:
        # Pad decimal to 3 digits and hex to 2 digits
        decimal_part = f"{byte:03d}"
        hex_part = f"{byte:02x}"
        encrypted_string += decimal_part + hex_part

    return encrypted_string

def decrypt_text(encrypted_text):
    """
    Decrypts text by parsing fixed-length segments for each byte.

    Args:
        encrypted_text: The encrypted string.

    Returns:
        The decrypted text.
    """

    byte_values = []
    chunk_size = 5  # Each chunk is 3 decimal digits + 2 hex digits

    for i in range(0, len(encrypted_text), chunk_size):
        chunk = encrypted_text[i:i+chunk_size]
        # Extract the first 3 characters as the decimal part
        if len(chunk) >= 3:
            decimal_str = chunk[:3]
            try:
                byte = int(decimal_str)
                byte_values.append(byte)
            except ValueError:
                # Skip invalid bytes
                pass

    decrypted_bytes = bytes(byte_values)
    return decrypted_bytes.decode('utf-8', errors='ignore')
