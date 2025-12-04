# crypto_utils.py
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_256, BLAKE2b
from hashlib import sha256
from Crypto.Protocol.KDF import PBKDF2

def generate_aes_key():
    return get_random_bytes(32)  # 256-bit

def aes_encrypt_bytes(plaintext_bytes, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return cipher.nonce, ciphertext, tag

def aes_decrypt_bytes(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def generate_rsa(bits=2048):
    key = RSA.generate(bits)
    priv = key.export_key()
    pub = key.publickey().export_key()
    return priv, pub

def rsa_encrypt_bytes(plaintext_bytes, public_key_bytes):
    key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(plaintext_bytes)

def rsa_decrypt_bytes(ciphertext_bytes, private_key_bytes):
    key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext_bytes)

def hash_sha256_bytes(data_bytes):
    h = sha256()
    h.update(data_bytes)
    return h.hexdigest()

def hash_sha3_bytes(data_bytes):
    h = SHA3_256.new()
    h.update(data_bytes)
    return h.hexdigest()

def hash_blake2b_bytes(data_bytes):
    h = BLAKE2b.new(digest_bits=256)
    h.update(data_bytes)
    return h.hexdigest()

def derive_key_from_password(password, salt=None, iterations=200000):
    if salt is None:
        salt = get_random_bytes(16)
    key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=iterations)
    return key, salt
