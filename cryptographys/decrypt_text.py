# cryptography/decrypt_text.py
import os
import json
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1  # ← Added MGF1
from cryptography.hazmat.primitives.hashes import SHA256              # ← Critical: Added SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decrypt_text() -> str:
    """
    Opens a .cg_text file, asks for the private key, decrypts the text,
    and saves the plaintext to a user-chosen location.
    Returns: path to the saved decrypted text file
    """
    # Step 1: Select encrypted text file
    input_path = filedialog.askopenfilename(
        title="Select Encrypted Text File",
        filetypes=[
            ("CryptoGuard Encrypted Text", "*.cg_text"),
            ("JSON Files", "*.json"),
            ("All Files", "*.*")
        ]
    )
    if not input_path:
        raise ValueError("No encrypted file selected!")

    # Load the JSON package
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            package = json.load(f)
    except Exception as e:
        raise ValueError(f"Invalid or corrupted encrypted file:\n{str(e)}")

    key_name = package.get("key_name", "unknown")
    try:
        enc_aes_key = bytes.fromhex(package["enc_aes_key"])
        nonce = bytes.fromhex(package["nonce"])
        ciphertext = bytes.fromhex(package["ciphertext"])
    except (KeyError, ValueError) as e:
        raise ValueError(f"Missing or invalid data in encrypted file:\n{str(e)}")

    # Step 2: Select private key
    private_key_path = filedialog.askopenfilename(
        title=f"Select Private Key (hint: {key_name}_private.pem)",
        filetypes=[
            ("PEM Private Key", "*_private.pem"),
            ("PEM Files", "*.pem"),
            ("All Files", "*.*")
        ]
    )
    if not private_key_path:
        raise ValueError("No private key selected!")

    # Optional warning if key name doesn't match
    if key_name != "unknown" and key_name not in os.path.basename(private_key_path):
        if not messagebox.askyesno(
            "Key Mismatch Warning",
            "The private key filename doesn't match the expected name.\n"
            "This might be the wrong key.\n\n"
            "Continue anyway?"
        ):
            raise ValueError("Decryption cancelled by user.")

    # Load private key
    try:
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        raise ValueError(f"Failed to load private key:\n{str(e)}")

    # Step 3: Decrypt the AES session key using RSA-OAEP
    try:
        aes_key = private_key.decrypt(
            enc_aes_key,
            OAEP(
                mgf=MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"Decryption failed — likely wrong private key:\n{str(e)}")

    # Step 4: Decrypt the actual text with AES-GCM
    try:
        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        plaintext = plaintext_bytes.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to decrypt text (corrupted data or wrong key):\n{str(e)}")

    # Step 5: Save decrypted text
    suggested_name = "decrypted_text.txt"
    save_path = filedialog.asksaveasfilename(
        title="Save Decrypted Text As",
        defaultextension=".txt",
        initialfile=suggested_name,
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if not save_path:
        raise ValueError("Save cancelled by user.")

    # Avoid overwrite with numbering
    final_path = save_path
    counter = 1
    base_dir = os.path.dirname(final_path)
    base_name = os.path.basename(final_path).rsplit(".", 1)[0]
    ext = ".txt"

    while os.path.exists(final_path):
        final_path = os.path.join(base_dir, f"{base_name}_{counter}{ext}")
        counter += 1

    try:
        with open(final_path, "w", encoding="utf-8") as f:
            f.write(plaintext)
    except Exception as e:
        raise ValueError(f"Failed to save decrypted file:\n{str(e)}")

    messagebox.showinfo(
        "Decryption Successful!",
        f"Text decrypted and saved to:\n\n{final_path}\n\n"
        f"You can now open and read the file safely."
    )

    return final_path