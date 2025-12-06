"""
Utility functions to save/load RSA and AES keys.
"""

import os
from Crypto.PublicKey import RSA


def load_rsa_private(key_dir: str):
    path = os.path.join(key_dir, "rsa_private.pem")
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_rsa_public(key_dir: str):
    path = os.path.join(key_dir, "rsa_public.pem")
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_aes_key(key_dir: str):
    path = os.path.join(key_dir, "aes.key")
    with open(path, "rb") as f:
        return f.read()


def save_custom_rsa_key(key_data: bytes, key_dir: str, private=True):
    filename = "rsa_private_custom.pem" if private else "rsa_public_custom.pem"
    path = os.path.join(key_dir, filename)
    with open(path, "wb") as f:
        f.write(key_data)
    return path


def save_custom_aes_key(key_data: bytes, key_dir: str):
    path = os.path.join(key_dir, "aes_custom.key")
    with open(path, "wb") as f:
        f.write(key_data)
    return path