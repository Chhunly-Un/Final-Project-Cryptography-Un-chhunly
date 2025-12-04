import base64, secrets, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

AES_KEY_SIZE = 32  # 256-bit

def generate_aes_key():
    return secrets.token_bytes(AES_KEY_SIZE)

def aes_encrypt_bytes(key: bytes, plaintext: bytes):
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return {'nonce': base64.b64encode(nonce).decode('utf-8'), 'ct': base64.b64encode(ct).decode('utf-8')}

def aes_decrypt_bytes(key: bytes, blob: dict):
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(blob['nonce'])
    ct = base64.b64decode(blob['ct'])
    return aesgcm.decrypt(nonce, ct, None)

def generate_rsa_keypair(bits=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    return private_key, private_key.public_key()

def rsa_encrypt(public_key, plaintext: bytes):
    return public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(private_key, ciphertext: bytes):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def serialize_private_key(private_key, passphrase: bytes = None):
    alg = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=alg
    )

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_private_key(pem_bytes: bytes, passphrase: bytes = None):
    return serialization.load_pem_private_key(pem_bytes, password=passphrase, backend=default_backend())

def load_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())
