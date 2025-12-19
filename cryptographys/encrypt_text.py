# cryptographys/encrypt_text.py
import os
import uuid
import json
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_text(plaintext: str, sign: bool = True) -> tuple[str, str, str, str]:
    key_name = f"text_{uuid.uuid4().hex[:8]}"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    data = plaintext.encode('utf-8')

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)

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

    package = {
        "key_name": key_name,
        "enc_aes_key": enc_aes_key.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": signature_hex
    }
    encrypted_json = json.dumps(package, indent=2)

    # Save dialogs (unchanged)
    messagebox.showinfo("Save Files", "Save public key, private key, and encrypted text file.")

    public_key_path = filedialog.asksaveasfilename(title=f"Save Public Key — {key_name}_public.pem", defaultextension=".pem", initialfile=f"{key_name}_public.pem")
    if not public_key_path: raise ValueError("Cancelled")

    private_key_path = filedialog.asksaveasfilename(title=f"Save Private Key — {key_name}_private.pem (KEEP SAFE!)", defaultextension=".pem", initialfile=f"{key_name}_private.pem")
    if not private_key_path: raise ValueError("Cancelled")

    encrypted_path = filedialog.asksaveasfilename(title="Save Encrypted Text File", defaultextension=".cg_text", initialfile=f"text_encrypted_{key_name}.cg_text")
    if not encrypted_path: raise ValueError("Cancelled")

    with open(public_key_path, "wb") as f: f.write(public_pem)
    with open(private_key_path, "wb") as f: f.write(private_pem)
    with open(encrypted_path, "w", encoding="utf-8") as f: f.write(encrypted_json)

    sign_text = "with digital signature " if sign else ""
    messagebox.showinfo("Success!", f"Text encrypted {sign_text}successfully!")

    return encrypted_json, encrypted_path, public_key_path, private_key_path