from cryptography.fernet import Fernet
import base64
import os
import random

def generate_key():
    """Generate a secure AES key"""
    return Fernet.generate_key()

def encrypt_message(message, key):
    """Encrypt a message using AES encryption"""
    try:
        fernet = Fernet(key)
        encrypted = fernet.encrypt(message.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")

def decrypt_message(encrypted_message, key):
    """Decrypt a message using AES decryption"""
    try:
        fernet = Fernet(key)
        # Decode from base64 first
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode())
        decrypted = fernet.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def generate_otp():
    """Generate a secure 6-digit OTP"""
    return str(random.randint(100000, 999999))