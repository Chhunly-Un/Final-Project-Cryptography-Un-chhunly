import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_PUBLIC_NAME = 'rsa_public.pem'


def _load_rsa_public(key_dir: str):
    path = os.path.join(key_dir, RSA_PUBLIC_NAME)
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def encrypt_file(in_path: str, out_path: str, key_dir: str):
    with open(in_path, 'rb') as f:
        data = f.read()
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    pub = _load_rsa_public(key_dir)
    enc_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    from struct import pack
    header = pack('>I', len(enc_key))
    with open(out_path, 'wb') as f:
        f.write(header + enc_key + nonce + ciphertext)