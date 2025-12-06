# cryptography/encrypt_text.py
import os
import base64
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def encrypt_text(plaintext: str) -> tuple[str, str]:
    """
    Returns: (encrypted_data, key_name)
    """
    # Generate new key pair for this text
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Unique key name
    import uuid
    key_name = f"text_{uuid.uuid4().hex[:8]}"
    os.makedirs("keys", exist_ok=True)

    with open(f"keys/{key_name}_private.pem", "wb") as f:
        f.write(private_key)
    with open(f"keys/{key_name}_public.pem", "wb") as f:
        f.write(public_key)

    # Hybrid encryption
    session_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(plaintext.encode(), 16))

    cipher_rsa = PKCS1_OAEP.new(key.publickey())
    enc_session_key = cipher_rsa.encrypt(session_key)

    package = {
        "key_name": key_name,
        "enc_session_key": base64.b64encode(enc_session_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

    encrypted_b64 = base64.b64encode(pickle.dumps(package)).decode()
    return encrypted_b64, key_name