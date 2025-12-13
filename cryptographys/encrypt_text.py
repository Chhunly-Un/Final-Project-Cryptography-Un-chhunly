# cryptography/encrypt_text.py
import os
import uuid
import json
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1  # ← Added MGF1
from cryptography.hazmat.primitives.hashes import SHA256  # ← Critical: Import SHA256 directly
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_text(plaintext: str) -> tuple[str, str, str, str]:
    """
    Returns: (encrypted_json_string, encrypted_file_path, public_key_path, private_key_path)
    The JSON string can be copied or shared separately.
    """
    key_name = f"text_{uuid.uuid4().hex[:8]}"

    # Generate RSA-3072 key pair
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

    data = plaintext.encode('utf-8')

    # AES-256-GCM authenticated encryption
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)  # 96-bit nonce
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)

    # Encrypt AES key with RSA-OAEP
    enc_aes_key = public_key.encrypt(
        aes_key,
        OAEP(
            mgf=MGF1(algorithm=SHA256()),  # Now works: MGF1 and SHA256 are imported
            algorithm=SHA256(),
            label=None
        )
    )

    # Create JSON package (human-readable and safe)
    package = {
        "key_name": key_name,
        "enc_aes_key": enc_aes_key.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }
    encrypted_json = json.dumps(package, indent=2)

    # Prompt user to save files
    messagebox.showinfo(
        "Save Files",
        "Next, you will choose where to save:\n"
        "• Public key\n"
        "• Private key (KEEP THIS SAFE!)\n"
        "• Encrypted text file"
    )

    public_key_path = filedialog.asksaveasfilename(
        title=f"Save Public Key — {key_name}_public.pem",
        defaultextension=".pem",
        initialfile=f"{key_name}_public.pem",
        filetypes=[("PEM Public Key", "*.pem")]
    )
    if not public_key_path:
        raise ValueError("Public key save cancelled.")

    private_key_path = filedialog.asksaveasfilename(
        title=f"Save Private Key — {key_name}_private.pem (VERY IMPORTANT — KEEP SAFE!)",
        defaultextension=".pem",
        initialfile=f"{key_name}_private.pem",
        filetypes=[("PEM Private Key", "*.pem")]
    )
    if not private_key_path:
        raise ValueError("Private key save cancelled.")

    encrypted_path = filedialog.asksaveasfilename(
        title="Save Encrypted Text File",
        defaultextension=".cg_text",
        initialfile=f"text_encrypted_{key_name}.cg_text",
        filetypes=[("CryptoGuard Encrypted Text", "*.cg_text")]
    )
    if not encrypted_path:
        raise ValueError("Encrypted text save cancelled.")

    # Save all files
    with open(public_key_path, "wb") as f:
        f.write(public_pem)
    with open(private_key_path, "wb") as f:
        f.write(private_pem)
    with open(encrypted_path, "w", encoding="utf-8") as f:
        f.write(encrypted_json)

    preview = encrypted_json[:300] + "..." if len(encrypted_json) > 300 else encrypted_json
    messagebox.showinfo(
        "Encryption Complete!",
        f"Text encrypted successfully!\n\n"
        f"• Encrypted file: {os.path.basename(encrypted_path)}\n"
        f"• Public key: {os.path.basename(public_key_path)}\n"
        f"• Private key: {os.path.basename(private_key_path)}\n\n"
        f"You can also copy the encrypted JSON below:\n\n{preview}"
    )

    return encrypted_json, encrypted_path, public_key_path, private_key_path