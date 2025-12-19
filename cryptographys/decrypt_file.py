# cryptographys/decrypt_file.py
import os
import json
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decrypt_file() -> str:
    input_path = filedialog.askopenfilename(
        title="Select CryptoGuard Encrypted File",
        filetypes=[("CryptoGuard Encrypted", "*.cg_enc"), ("All Files", "*.*")]
    )
    if not input_path: raise ValueError("No file selected!")

    with open(input_path, "r", encoding="utf-8") as f:
        package = json.load(f)

    key_name = package["key_name"]
    enc_aes_key = bytes.fromhex(package["enc_aes_key"])
    nonce = bytes.fromhex(package["nonce"])
    ciphertext = bytes.fromhex(package["ciphertext"])
    signature_hex = package.get("signature")  # May be None or missing

    private_key_path = filedialog.askopenfilename(
        title=f"Select Private Key (hint: {key_name}_private.pem)",
        filetypes=[("Private Key Files", "*_private.pem"), ("All Files", "*.*")]
    )
    if not private_key_path: raise ValueError("No private key selected!")

    if key_name not in os.path.basename(private_key_path):
        if not messagebox.askyesno("Warning", "Private key name doesn't match the hint.\nContinue anyway?"):
            raise ValueError("Incorrect private key!")

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    aes_key = private_key.decrypt(
        enc_aes_key,
        OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    # === Signature Verification ===
    public_key = private_key.public_key()
    if signature_hex:
        try:
            digest = hashes.Hash(SHA256())
            digest.update(plaintext)
            public_key.verify(
                bytes.fromhex(signature_hex),
                digest,
                padding.PKCS1v15(),
                SHA256()
            )
            sig_msg = "✅ DIGITAL SIGNATURE VERIFIED — Data is authentic and untampered!"
        except Exception:
            sig_msg = "⚠️ SIGNATURE VERIFICATION FAILED — File may have been tampered with!"
            messagebox.showwarning("Tampering Detected", sig_msg)
    else:
        sig_msg = "ℹ️ No digital signature present (encrypted without signing)"

    # Save decrypted file
    original_name = os.path.basename(input_path).removesuffix(".cg_enc")
    save_path = filedialog.asksaveasfilename(
        title="Save Decrypted File As",
        initialfile=f"{original_name}_DECRYPTED"
    )
    if not save_path: raise ValueError("Save cancelled!")

    final_path = save_path
    counter = 1
    dir_path = os.path.dirname(save_path)
    base_name, ext = os.path.splitext(original_name)

    while os.path.exists(final_path):
        final_path = os.path.join(dir_path, f"{base_name}_DECRYPTED_{counter}{ext}")
        counter += 1

    with open(final_path, "wb") as f:
        f.write(plaintext)

    messagebox.showinfo("Success!", f"File decrypted successfully!\n\nSaved to:\n{final_path}\n\n{sig_msg}")
    return final_path