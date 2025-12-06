import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_PRIVATE_NAME = 'rsa_private.pem'


def _load_rsa_private(key_dir: str):
    path = os.path.join(key_dir, RSA_PRIVATE_NAME)
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def decrypt_file(in_path: str, out_path: str, key_dir: str):
    with open(in_path, 'rb') as f:
        blob = f.read()
    from struct import unpack
    (klen,) = unpack('>I', blob[:4])
    enc_key = blob[4:4 + klen]
    rest = blob[4 + klen:]
    nonce = rest[:12]
    ciphertext = rest[12:]

    priv = _load_rsa_private(key_dir)
    aes_key = priv.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    with open(out_path, 'wb') as f:
        f.write(plaintext)