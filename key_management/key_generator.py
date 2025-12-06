# key_management/key_generator.py
from Crypto.PublicKey import RSA
import os
from tkinter import messagebox
import datetime

def generate_rsa_keys():
    try:
        # Generate 2048-bit RSA key (you can upgrade to 4096 later)
        print("Generating 2048-bit RSA key pair... (this may take a few seconds)")
        key = RSA.generate(2048)

        # Export keys in PEM format
        private_key_pem = key.export_key()
        public_key_pem = key.publickey().export_key()

        # Create keys folder
        os.makedirs("keys", exist_ok=True)

        private_path = "keys/private_key.pem"
        public_path = "keys/public_key.pem"

        # Write private key
        with open(private_path, "wb") as f:
            f.write(private_key_pem)

        # Write public key
        with open(public_path, "wb") as f:
            f.write(public_key_pem)

        # Optional: Add timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("keys/generation_log.txt", "a") as log:
            log.write(f"[{timestamp}] New RSA-2048 key pair generated\n")

        # Success message for GUI
        messagebox.showinfo(
            "Success!",
            "RSA Key Pair Generated Successfully!\n\n"
            "Private Key: keys/private_key.pem\n"
            "Public Key:  keys/public_key.pem\n\n"
            "Keep your private key SAFE and NEVER share it!",
            icon="info"
        )
        print("RSA key pair generated and saved in /keys folder")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate keys:\n{str(e)}")
        print(f"Error generating keys: {e}")