import rsa
import os
import struct
from Crypto.Cipher import AES

# Generate RSA keys
def generate_rsa_keys():
    return rsa.newkeys(2048)

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce + tag + ciphertext

def decrypt_message(encrypted_data, key):
    try:
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except:
        return "[Decryption Error]"

def encrypt_aes_key(aes_key, public_partner):
    return rsa.encrypt(aes_key, public_partner)

def decrypt_aes_key(encrypted_aes_key, private_key):
    return rsa.decrypt(encrypted_aes_key, private_key)
