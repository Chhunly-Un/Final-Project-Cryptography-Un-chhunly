# cryptography/decrypt_text.py
import os
import base64
import pickle
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from tkinter import filedialog, messagebox

def decrypt_text(encrypted_b64: str) -> str:
    try:
        package = pickle.loads(base64.b64decode(encrypted_b64))
    except:
        raise ValueError("Invalid encrypted text!")

    key_name = package["key_name"]
    enc_session_key = base64.b64decode(package["enc_session_key"])
    iv = base64.b64decode(package["iv"])
    ciphertext = base64.b64decode(package["ciphertext"])

    # Ask for private key
    private_path = filedialog.askopenfilename(
        initialdir="keys",
        title=f"Select private key: {key_name}_private.pem",
        filetypes=[("Private Key", "*_private.pem")]
    )
    if not private_path:
        raise ValueError("No key selected!")

    if key_name not in private_path:
        if not messagebox.askyesno("Warning", "Key name doesn't match! Continue?"):
            raise ValueError("Wrong key!")

    private_key = RSA.import_key(open(private_path, "rb").read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), 16).decode()

    # SAVE TO decrypted_folder AS .txt FILE
    os.makedirs("decrypted_folder", exist_ok=True)
    
    # Create safe filename
    import hashlib
    safe_name = hashlib.md5(encrypted_b64.encode()).hexdigest()[:12]
    output_path = f"decrypted_folder/text_decrypted_{safe_name}.txt"
    
    counter = 1
    final_path = output_path
    while os.path.exists(final_path):
        final_path = f"decrypted_folder/text_decrypted_{safe_name}_{counter}.txt"
        counter += 1

    with open(final_path, "w", encoding="utf-8") as f:
        f.write(plaintext)

    return final_path  # Return path so GUI can show it