# cryptography/decrypt_file.py
import os
import base64
import pickle
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from tkinter import filedialog, messagebox

def decrypt_file(input_path: str) -> str:
    # Read encrypted package
    with open(input_path, "rb") as f:
        package = pickle.loads(f.read())

    key_name = package["key_name"]
    enc_session_key = base64.b64decode(package["enc_session_key"])
    iv = base64.b64decode(package["iv"])
    ciphertext = base64.b64decode(package["ciphertext"])

    # Ask for correct private key
    private_key_path = filedialog.askopenfilename(
        initialdir="keys",
        title=f"Select private key: {key_name}_private.pem",
        filetypes=[("Private Key", "*_private.pem")]
    )
    if not private_key_path:
        raise ValueError("No private key selected!")

    if key_name not in os.path.basename(private_key_path):
        if not messagebox.askyesno("Warning", "Key name doesn't match! Continue anyway?"):
            raise ValueError("Wrong key selected!")

    private_key = RSA.import_key(open(private_key_path, "rb").read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), 16)

    # CREATE decrypted_folder IF NOT EXISTS
    decrypted_folder = "decrypted_folder"
    os.makedirs(decrypted_folder, exist_ok=True)

    # Get original filename and save
    original_name = os.path.basename(input_path).replace(".cg_enc", "")
    output_path = os.path.join(decrypted_folder, original_name + "_DECRYPTED")

    # Avoid overwrite
    counter = 1
    final_path = output_path
    while os.path.exists(final_path):
        name_part = original_name
        ext = ""
        if "." in original_name:
            name_part, ext = original_name.rsplit(".", 1)
            ext = "." + ext
        final_path = os.path.join(decrypted_folder, f"{name_part}_DECRYPTED_{counter}{ext}")
        counter += 1

    with open(final_path, "wb") as f:
        f.write(plaintext)

    return final_path  # Return full path to decrypted file