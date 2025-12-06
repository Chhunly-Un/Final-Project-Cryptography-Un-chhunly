"""
Generates RSA key pair and AES symmetric key.
Saves them into the key directory.
"""


import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes




def ensure_keys_exist(key_dir: str):
    os.makedirs(key_dir, exist_ok=True)


    rsa_private_path = os.path.join(key_dir, "rsa_private.pem")
    rsa_public_path = os.path.join(key_dir, "rsa_public.pem")
    aes_key_path = os.path.join(key_dir, "aes.key")


# Generate RSA keys if missing
    if not os.path.exists(rsa_private_path) or not os.path.exists(rsa_public_path):
        key = RSA.generate(2048)
    with open(rsa_private_path, "wb") as f:
        f.write(key.export_key())
    with open(rsa_public_path, "wb") as f:
        f.write(key.publickey().export_key())


# Generate AES key if missing
    if not os.path.exists(aes_key_path):
        aes_key = get_random_bytes(32) # 256-bit AES key
        with open(aes_key_path, "wb") as f:
            f.write(aes_key)


    return True