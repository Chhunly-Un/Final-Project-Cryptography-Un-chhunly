import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_PRIVATE_NAME = 'rsa_private.pem'


def _load_rsa_private(key_dir: str):
    path = os.path.join(key_dir, RSA_PRIVATE_NAME)
    with open(path, 'rb') as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None)


def decrypt_text(blob: bytes, key_dir: str) -> str:
    from struct import unpack
    # parse header
    if len(blob) < 4:
        raise ValueError('Blob too small')
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
    pt = aesgcm.decrypt(nonce, ciphertext, None)
    return pt.decode('utf-8')