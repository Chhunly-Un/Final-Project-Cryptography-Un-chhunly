# cryptographys/encrypt_file.py
import os
import json
import uuid
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(input_path: str, sign: bool = True) -> tuple[str, str, str]:
    filename = os.path.splitext(os.path.basename(input_path))[0]
    key_name = f"{filename}_{uuid.uuid4().hex[:8]}"

    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Read data
    with open(input_path, "rb") as f:
        data = f.read()

    # AES encryption
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)

    # Encrypt AES key
    enc_aes_key = public_key.encrypt(
        aes_key,
        OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    )

    # === FIXED Digital Signature ===
    signature_hex = None
    if sign:
        digest = hashes.Hash(SHA256())
        digest.update(data)
        hash_bytes = digest.finalize()  # <-- Critical fix
        signature = private_key.sign(
            hash_bytes,
            padding.PKCS1v15(),
            SHA256()
        )
        signature_hex = signature.hex()

    # Package
    package = {
        "key_name": key_name,
        "enc_aes_key": enc_aes_key.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": signature_hex
    }

    # Save dialogs (unchanged)
    messagebox.showinfo("Save Files", "Choose save locations for keys and encrypted file.")

    public_key_path = filedialog.asksaveasfilename(title=f"Save Public Key ({key_name}_public.pem)", defaultextension=".pem", initialfile=f"{key_name}_public.pem")
    if not public_key_path: raise ValueError("Cancelled")

    private_key_path = filedialog.asksaveasfilename(title=f"Save Private Key ({key_name}_private.pem) — KEEP SAFE!", defaultextension=".pem", initialfile=f"{key_name}_private.pem")
    if not private_key_path: raise ValueError("Cancelled")

    encrypted_path = filedialog.asksaveasfilename(title="Save Encrypted File", defaultextension=".cg_enc", initialfile=f"{filename}.cg_enc")
    if not encrypted_path: raise ValueError("Cancelled")

    with open(public_key_path, "wb") as f: f.write(public_pem)
    with open(private_key_path, "wb") as f: f.write(private_pem)
    with open(encrypted_path, "w", encoding="utf-8") as f: json.dump(package, f, indent=2)

    sign_text = "with digital signature " if sign else ""
    messagebox.showinfo("Success!", f"File encrypted {sign_text}successfully!\nSaved to:\n{encrypted_path}")

    return encrypted_path, public_key_path, private_key_path