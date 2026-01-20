from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Random import get_random_bytes
import hashlib
import json

# ---------- RSA ----------
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()

def rsa_encrypt(public_key, data_bytes):
    """Encrypt with RSA - simple wrapper"""
    if isinstance(data_bytes, str):
        data_bytes = data_bytes.encode()
    
    # Convert data to JSON string for encryption
    if isinstance(data_bytes, dict):
        data_bytes = json.dumps(data_bytes).encode()
    
    # For large data, we need to split or use hybrid encryption
    # For DH params (small), we can encrypt directly
    cipher = PKCS1_OAEP.new(public_key)
    
    # RSA can only encrypt limited size
    max_size = 190  # For 2048-bit RSA with OAEP
    
    if len(data_bytes) <= max_size:
        return cipher.encrypt(data_bytes)
    else:
        # For larger data, we'd use hybrid encryption
        # But DH params are small, so just truncate/error
        raise ValueError(f"Data too large for RSA: {len(data_bytes)} > {max_size}")

def rsa_decrypt(private_key, ciphertext):
    """Decrypt with RSA"""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)

# ---------- Diffie-Hellman ----------
def dh_generate_params():
    q = 7919  # large prime
    alpha = 2
    return q, alpha

def dh_generate_private_key():
    return get_random_bytes(2)[0] + 1000  # simple random private key

def dh_generate_public_key(alpha, private, q):
    return pow(alpha, private, q)

def dh_shared_secret(their_public, private, q):
    return pow(their_public, private, q)

# ---------- DES-CFB ----------
def derive_des_key(shared_secret):
    hashed = hashlib.sha256(str(shared_secret).encode()).digest()
    return hashed[:8]  # DES key 8 bytes

def des_encrypt(key, iv, plaintext):
    cipher = DES.new(key, DES.MODE_CFB, iv=iv)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    return cipher.encrypt(plaintext)

def des_decrypt(key, iv, ciphertext):
    cipher = DES.new(key, DES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)