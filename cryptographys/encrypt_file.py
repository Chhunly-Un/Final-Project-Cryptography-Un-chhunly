# cryptography/encrypt_file.py
import os
import base64
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def encrypt_file(input_path: str) -> tuple[str, str]:
    filename = os.path.splitext(os.path.basename(input_path))[0]
    key_name = f"{filename}_{__import__('uuid').uuid4().hex[:6]}"

    # Generate new key pair
    key = RSA.generate(2048)
    os.makedirs("keys", exist_ok=True)
    with open(f"keys/{key_name}_private.pem", "wb") as f:
        f.write(key.export_key())
    with open(f"keys/{key_name}_public.pem", "wb") as f:
        f.write(key.publickey().export_key())

    # Encrypt file
    with open(input_path, "rb") as f:
        data = f.read()

    session_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(data, 16))

    cipher_rsa = PKCS1_OAEP.new(key.publickey())
    enc_session_key = cipher_rsa.encrypt(session_key)

    package = {
        "key_name": key_name,
        "enc_session_key": base64.b64encode(enc_session_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

    os.makedirs("secured_files", exist_ok=True)
    output_path = f"secured_files/{filename}.cg_enc"
    with open(output_path, "wb") as f:
        f.write(pickle.dumps(package))

    return output_path, key_name