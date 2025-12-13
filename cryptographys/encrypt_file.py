# cryptographys/encrypt_file.py
import os
import json
import uuid
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256  # ← Critical fix
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(input_path: str) -> tuple[str, str, str]:
    """
    Returns: (encrypted_file_path, public_key_path, private_key_path)
    Supports encryption of ANY file type.
    """
    filename = os.path.splitext(os.path.basename(input_path))[0]
    key_name = f"{filename}_{uuid.uuid4().hex[:8]}"

    # Generate strong RSA-3072 key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_key = private_key.public_key()

    # Serialize keys in PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Read file (binary - works for images, videos, docs, etc.)
    with open(input_path, "rb") as f:
        data = f.read()

    # AES-256-GCM authenticated encryption
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)

    # Encrypt AES key with RSA-OAEP
    enc_aes_key = public_key.encrypt(
        aes_key,
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    # Create package
    package = {
        "key_name": key_name,
        "enc_aes_key": enc_aes_key.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }

    # Let user choose save locations
    messagebox.showinfo("Save Files", "Now choose where to save the public key, private key, and encrypted file.")

    public_key_path = filedialog.asksaveasfilename(
        title=f"Save Public Key ({key_name}_public.pem)",
        defaultextension=".pem",
        initialfile=f"{key_name}_public.pem",
        filetypes=[("PEM Files", "*.pem")]
    )
    if not public_key_path:
        raise ValueError("Public key save cancelled.")

    private_key_path = filedialog.asksaveasfilename(
        title=f"Save Private Key ({key_name}_private.pem) — KEEP THIS SAFE AND PRIVATE!",
        defaultextension=".pem",
        initialfile=f"{key_name}_private.pem",
        filetypes=[("PEM Files", "*.pem")]
    )
    if not private_key_path:
        raise ValueError("Private key save cancelled.")

    encrypted_path = filedialog.asksaveasfilename(
        title="Save Encrypted File",
        defaultextension=".cg_enc",
        initialfile=f"{filename}.cg_enc",
        filetypes=[("CryptoGuard Encrypted File", "*.cg_enc")]
    )
    if not encrypted_path:
        raise ValueError("Encrypted file save cancelled.")

    # Save all files
    with open(public_key_path, "wb") as f:
        f.write(public_pem)
    with open(private_key_path, "wb") as f:
        f.write(private_pem)
    with open(encrypted_path, "w", encoding="utf-8") as f:
        json.dump(package, f, indent=2)

    messagebox.showinfo("Success!", f"File encrypted successfully!\n\nSaved to:\n{encrypted_path}")

    return encrypted_path, public_key_path, private_key_path