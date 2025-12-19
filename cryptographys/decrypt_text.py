# cryptographys/decrypt_text.py
import os
import json
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decrypt_text() -> str:
    input_path = filedialog.askopenfilename(
        title="Select Encrypted Text File",
        filetypes=[("CryptoGuard Encrypted Text", "*.cg_text"), ("JSON Files", "*.json"), ("All Files", "*.*")]
    )
    if not input_path: raise ValueError("No encrypted file selected!")

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            package = json.load(f)
    except Exception as e:
        raise ValueError(f"Invalid or corrupted file:\n{str(e)}")

    key_name = package.get("key_name", "unknown")
    enc_aes_key = bytes.fromhex(package["enc_aes_key"])
    nonce = bytes.fromhex(package["nonce"])
    ciphertext = bytes.fromhex(package["ciphertext"])
    signature_hex = package.get("signature")

    private_key_path = filedialog.askopenfilename(
        title=f"Select Private Key (hint: {key_name}_private.pem)",
        filetypes=[("PEM Private Key", "*_private.pem"), ("All Files", "*.*")]
    )
    if not private_key_path: raise ValueError("No private key selected!")

    if key_name != "unknown" and key_name not in os.path.basename(private_key_path):
        if not messagebox.askyesno("Key Mismatch", "Key name doesn't match hint. Continue anyway?"):
            raise ValueError("Cancelled.")

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    aes_key = private_key.decrypt(
        enc_aes_key,
        OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    )

    aesgcm = AESGCM(aes_key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    plaintext = plaintext_bytes.decode('utf-8')

    # === Signature Verification ===
    public_key = private_key.public_key()
    if signature_hex:
        try:
            digest = hashes.Hash(SHA256())
            digest.update(plaintext_bytes)
            public_key.verify(
                bytes.fromhex(signature_hex),
                digest,
                padding.PKCS1v15(),
                SHA256()
            )
            sig_msg = "✅ Digital signature verified — authentic and untampered!"
        except Exception:
            sig_msg = "⚠️ SIGNATURE FAILED — Possible tampering detected!"
            messagebox.showwarning("Integrity Warning", sig_msg)
    else:
        sig_msg = "ℹ️ No digital signature (file was encrypted without one)"

    # Save decrypted text
    save_path = filedialog.asksaveasfilename(
        title="Save Decrypted Text As",
        defaultextension=".txt",
        initialfile="decrypted_text.txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if not save_path: raise ValueError("Save cancelled.")

    final_path = save_path
    counter = 1
    base_dir = os.path.dirname(final_path)
    base_name = os.path.basename(final_path).rsplit(".", 1)[0]

    while os.path.exists(final_path):
        final_path = os.path.join(base_dir, f"{base_name}_{counter}.txt")
        counter += 1

    with open(final_path, "w", encoding="utf-8") as f:
        f.write(plaintext)

    messagebox.showinfo("Decryption Successful!", f"Text decrypted and saved!\n\n{final_path}\n\n{sig_msg}")
    return final_path