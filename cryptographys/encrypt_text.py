import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_PUBLIC_NAME = 'rsa_public.pem'
AES_KEY_NAME = 'aes.key'


def _load_rsa_public(key_dir: str):
    path = os.path.join(key_dir, RSA_PUBLIC_NAME)
    with open(path, 'rb') as f:
        data = f.read()
    return serialization.load_pem_public_key(data)


def encrypt_text(plaintext: str, key_dir: str) -> bytes:
    # Hybrid: AES-GCM for content, RSA-OAEP for AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

    # encrypt AES key with RSA public
    pub = _load_rsa_public(key_dir)
    enc_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    # format: len(enc_key)[4 bytes big-endian] + enc_key + nonce + ciphertext
    from struct import pack
    header = pack('>I', len(enc_key))
    return header + enc_key + nonce + ciphertext