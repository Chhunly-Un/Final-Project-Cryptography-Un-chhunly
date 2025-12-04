# key_manager.py
import json
from pathlib import Path
from crypto_utils import derive_key_from_password, aes_encrypt_bytes, aes_decrypt_bytes
from Crypto.Random import get_random_bytes

STORAGE_DIR = Path.home() / ".crypto_guard_plus"
STORAGE_DIR.mkdir(exist_ok=True)

KEYSTORE_PATH = STORAGE_DIR / "keystore.bin"

def save_keystore(keys_dict, password):
    """
    keys_dict: dict with key_name -> bytes (raw key bytes or PEM bytes as bytes)
    password: string used to encrypt keystore
    """
    salt = get_random_bytes(16)
    key, _ = derive_key_from_password(password, salt)
    payload = {}
    for k, v in keys_dict.items():
        # store hex-encoded bytes
        payload[k] = v.hex()
    payload_bytes = json.dumps(payload).encode('utf-8')
    nonce, ciphertext, tag = aes_encrypt_bytes(payload_bytes, key)
    blob = {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    KEYSTORE_PATH.write_text(json.dumps(blob), encoding='utf-8')
    return True

def load_keystore(password):
    if not KEYSTORE_PATH.exists():
        raise FileNotFoundError("Keystore not found.")
    blob = json.loads(KEYSTORE_PATH.read_text(encoding='utf-8'))
    salt = bytes.fromhex(blob["salt"])
    nonce = bytes.fromhex(blob["nonce"])
    tag = bytes.fromhex(blob["tag"])
    ciphertext = bytes.fromhex(blob["ciphertext"])
    key, _ = derive_key_from_password(password, salt)
    plaintext = aes_decrypt_bytes(nonce, ciphertext, tag, key)
    payload = json.loads(plaintext.decode('utf-8'))
    # decode hex back to bytes
    return {k: bytes.fromhex(vhex) for k, vhex in payload.items()}
