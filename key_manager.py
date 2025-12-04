import json, base64, secrets
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

BASE_DIR = Path.home() / '.cryptoguard'
KEYS_DIR = BASE_DIR / 'keys'
KEYS_DIR.mkdir(parents=True, exist_ok=True)

KDF_SALT_SIZE = 16
KDF_ITERATIONS = 390000

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS, backend=default_backend())
    return kdf.derive(password.encode('utf-8'))

def encrypt_key_blob(aes_key: bytes, password: str) -> dict:
    salt = secrets.token_bytes(KDF_SALT_SIZE)
    wrapping_key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(wrapping_key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, aes_key, None)
    return {'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ct': base64.b64encode(ct).decode('utf-8')}

def decrypt_key_blob(blob: dict, password: str) -> bytes:
    salt = base64.b64decode(blob['salt'])
    nonce = base64.b64decode(blob['nonce'])
    ct = base64.b64decode(blob['ct'])
    wrapping_key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(wrapping_key)
    return aesgcm.decrypt(nonce, ct, None)

def save_blob_to_file(blob: dict, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(blob, f)

def load_blob_from_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)
