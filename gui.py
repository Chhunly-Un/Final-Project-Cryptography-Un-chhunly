"""
CryptoGuard Tkinter GUI (updated)
- Uses project modules under `cryptography/` and `key_management/` (from canvas)
- Adds Key Management integration (load/save/import keys)

Place this file as: CryptoGuard/gui.py
Run from main.py or directly.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# project crypto modules (ensure these packages/files exist in your project)
from cryptographys.encrypt_text import encrypt_text
from cryptographys.decrypt_text import decrypt_text
from cryptographys.encrypt_file import encrypt_file
from cryptographys.decrypt_file import decrypt_file
from key_management.generate_key import ensure_keys_exist
from key_management.store_key import (
    load_rsa_private,
    load_rsa_public,
    load_aes_key,
    save_custom_rsa_key,
    save_custom_aes_key,
)
from threat_analysis.weak_password_detection import is_weak_password
from threat_analysis.hash_collision_risk import check_hash_collision_risk
# For RSA key introspection (PyCryptodome RSA objects)
try:
    from Crypto.PublicKey import RSA as _RSA_PK
except Exception:
    _RSA_PK = None

# -------------------------------------------------------------
# GUI THEME COLORS (Tech-style)
# -------------------------------------------------------------
BG_DARK = "#0f0f1a"
BG_CARD = "#1a1a2e"
ACCENT = "#4cc9f0"
TEXT_LIGHT = "#e0e0e0"
GOOD = "#7ef29d"
WARN = "#ffb020"

# -------------------------------------------------------------
# MAIN GUI
# -------------------------------------------------------------
class CryptoGuardGUI(tk.Tk):
    def __init__(self, base_path):
        super().__init__()
        self.title("CryptoGuard — Secure Encryption Suite")
        self.geometry("980x660")
        self.configure(bg=BG_DARK)
        self.base = base_path
        self.key_dir = os.path.join(self.base, "keys")
        self.sec_dir = os.path.join(self.base, "secured_files")

        os.makedirs(self.key_dir, exist_ok=True)
        os.makedirs(self.sec_dir, exist_ok=True)
        ensure_keys_exist(self.key_dir)

        # cached key info
        self._rsa_priv = None
        self._rsa_pub = None
        self._aes = None

        self.build_ui()
        self.refresh_keys()

    # ---------------------------------------------------------
    # UI BUILDER
    # ---------------------------------------------------------
    def build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", font=("Segoe UI", 11, "bold"))

        # Tabs
        tab_text = self._build_encrypt_text_tab(notebook)
        tab_file = self._build_encrypt_file_tab(notebook)
        tab_keys = self._build_key_tab(notebook)
        tab_threat = self._build_threat_tab(notebook)

        notebook.add(tab_text, text="🔐 Text Crypto")
        notebook.add(tab_file, text="📁 File Crypto")
        notebook.add(tab_keys, text="🔑 Key Manager")
        notebook.add(tab_threat, text="⚠ Threat Analysis")

    # ---------------------------------------------------------
    # TEXT ENCRYPTION TAB
    # ---------------------------------------------------------
    def _build_encrypt_text_tab(self, parent):
        frame = tk.Frame(parent, bg=BG_DARK)

        lbl = tk.Label(frame, text="Text Encryption & Decryption", fg=ACCENT, bg=BG_DARK, font=("Segoe UI", 16, "bold"))
        lbl.pack(pady=10)

        self.text_input = tk.Text(frame, height=10, bg=BG_CARD, fg=TEXT_LIGHT, insertbackground="white")
        self.text_input.pack(fill="x", padx=20)

        btn_frame = tk.Frame(frame, bg=BG_DARK)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Encrypt", bg=ACCENT, fg="black", width=15, command=self.encrypt_text_action).pack(side="left", padx=10)
        tk.Button(btn_frame, text="Decrypt", bg=ACCENT, fg="black", width=15, command=self.decrypt_text_action).pack(side="left", padx=10)

        self.text_output = tk.Text(frame, height=10, bg=BG_CARD, fg=GOOD, insertbackground="white")
        self.text_output.pack(fill="x", padx=20, pady=10)

        return frame

    # Text encrypt
    def encrypt_text_action(self):
        plaintext = self.text_input.get("1.0", "end").strip()
        if not plaintext:
            messagebox.showerror("Error", "Enter text to encrypt.")
            return
        try:
            blob = encrypt_text(plaintext, self.key_dir)
            self.text_output.delete("1.0", "end")
            self.text_output.insert("end", blob.hex())
        except Exception as e:
            messagebox.showerror("Encryption error", str(e))

    # Text decrypt
    def decrypt_text_action(self):
        hexdata = self.text_input.get("1.0", "end").strip()
        try:
            raw = bytes.fromhex(hexdata)
            pt = decrypt_text(raw, self.key_dir)
            self.text_output.delete("1.0", "end")
            self.text_output.insert("end", pt)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt: {e}")

    # ---------------------------------------------------------
    # FILE ENCRYPTION TAB
    # ---------------------------------------------------------
    def _build_encrypt_file_tab(self, parent):
        frame = tk.Frame(parent, bg=BG_DARK)
        tk.Label(frame, text="File Encryption & Decryption", fg=ACCENT, bg=BG_DARK, font=("Segoe UI", 16, "bold")).pack(pady=10)

        # Encrypt
        tk.Button(frame, text="Encrypt File", bg=ACCENT, fg="black", width=24, command=self.encrypt_file_dialog).pack(pady=12)

        # Decrypt
        tk.Button(frame, text="Decrypt File", bg=ACCENT, fg="black", width=24, command=self.decrypt_file_dialog).pack(pady=12)

        # Recent secure folder
        tk.Label(frame, text=f"Secure folder: {self.sec_dir}", fg=TEXT_LIGHT, bg=BG_DARK).pack(pady=14)

        return frame

    def encrypt_file_dialog(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        out = os.path.join(self.sec_dir, os.path.basename(path) + ".enc")
        try:
            encrypt_file(path, out, self.key_dir)
            messagebox.showinfo("Encrypted", f"Encrypted file saved to:\n{out}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_file_dialog(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        out = filedialog.asksaveasfilename(defaultextension=".dec")
        if not out:
            return
        try:
            decrypt_file(path, out, self.key_dir)
            messagebox.showinfo("Decrypted", f"Decrypted file saved to:\n{out}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    # ---------------------------------------------------------
    # KEY MANAGER TAB
    # ---------------------------------------------------------
    def _build_key_tab(self, parent):
        frame = tk.Frame(parent, bg=BG_DARK)
        tk.Label(frame, text="Key Manager", fg=ACCENT, bg=BG_DARK, font=("Segoe UI", 16, "bold")).pack(pady=10)

        btn_row = tk.Frame(frame, bg=BG_DARK)
        btn_row.pack(pady=6)

        tk.Button(btn_row, text="Generate New RSA + AES", bg=ACCENT, fg="black", width=24, command=self.regen_keys).pack(side="left", padx=6)
        tk.Button(btn_row, text="Import Key File", bg=ACCENT, fg="black", width=18, command=self.import_key_file).pack(side="left", padx=6)

        info_frame = tk.Frame(frame, bg=BG_CARD, padx=10, pady=10)
        info_frame.pack(padx=20, pady=14, fill="x")

        tk.Label(info_frame, text="RSA Private:", fg=TEXT_LIGHT, bg=BG_CARD).grid(row=0, column=0, sticky="w")
        self.lbl_rsa_priv = tk.Label(info_frame, text="-", fg=GOOD, bg=BG_CARD)
        self.lbl_rsa_priv.grid(row=0, column=1, sticky="w")

        tk.Label(info_frame, text="RSA Public:", fg=TEXT_LIGHT, bg=BG_CARD).grid(row=1, column=0, sticky="w")
        self.lbl_rsa_pub = tk.Label(info_frame, text="-", fg=GOOD, bg=BG_CARD)
        self.lbl_rsa_pub.grid(row=1, column=1, sticky="w")

        tk.Label(info_frame, text="AES Key:", fg=TEXT_LIGHT, bg=BG_CARD).grid(row=2, column=0, sticky="w")
        self.lbl_aes = tk.Label(info_frame, text="-", fg=GOOD, bg=BG_CARD)
        self.lbl_aes.grid(row=2, column=1, sticky="w")

        # Action buttons
        act_frame = tk.Frame(frame, bg=BG_DARK)
        act_frame.pack(pady=6)

        tk.Button(act_frame, text="Export RSA Public", bg=ACCENT, fg="black", command=self.export_rsa_public).pack(side="left", padx=6)
        tk.Button(act_frame, text="Export RSA Private (save copy)", bg=ACCENT, fg="black", command=self.export_rsa_private).pack(side="left", padx=6)

        return frame

    def regen_keys(self):
        ensure_keys_exist(self.key_dir)
        self.refresh_keys()
        messagebox.showinfo("Keys", "Generated (or ensured) RSA + AES keys in keys/ directory")

    def refresh_keys(self):
        try:
            self._rsa_priv = load_rsa_private(self.key_dir)
        except Exception:
            self._rsa_priv = None
        try:
            self._rsa_pub = load_rsa_public(self.key_dir)
        except Exception:
            self._rsa_pub = None
        try:
            self._aes = load_aes_key(self.key_dir)
        except Exception:
            self._aes = None

        # update labels
        if self._rsa_priv is not None:
            try:
                bits = getattr(self._rsa_priv, 'size', None)
                if bits is None and hasattr(self._rsa_priv, 'n'):
                    bits = self._rsa_priv.n.bit_length()
                self.lbl_rsa_priv.config(text=f"{bits} bits")
            except Exception:
                self.lbl_rsa_priv.config(text="Loaded")
        else:
            self.lbl_rsa_priv.config(text="(missing)")

        if self._rsa_pub is not None:
            try:
                bits = getattr(self._rsa_pub, 'size', None)
                if bits is None and hasattr(self._rsa_pub, 'n'):
                    bits = self._rsa_pub.n.bit_length()
                self.lbl_rsa_pub.config(text=f"{bits} bits")
            except Exception:
                self.lbl_rsa_pub.config(text="Loaded")
        else:
            self.lbl_rsa_pub.config(text="(missing)")

        if self._aes is not None:
            self.lbl_aes.config(text=f"{len(self._aes)*8} bits")
        else:
            self.lbl_aes.config(text="(missing)")

    def import_key_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        try:
            with open(path, 'rb') as f:
                data = f.read()
            # simple heuristic: PEM text contains 'BEGIN'
            if b'BEGIN' in data:
                # treat as RSA (private or public)
                # ask user whether private or public
                kind = messagebox.askquestion("Key type", "Is this a PRIVATE key? (No = public)")
                private = (kind == 'yes')
                save_custom_rsa_key(data, self.key_dir, private=private)
                messagebox.showinfo("Imported", f"Saved custom RSA {'private' if private else 'public'} key to keys/")
            else:
                # treat as raw AES key
                save_custom_aes_key(data, self.key_dir)
                messagebox.showinfo("Imported", "Saved custom AES key to keys/")
            self.refresh_keys()
        except Exception as e:
            messagebox.showerror("Import failed", str(e))

    def export_rsa_public(self):
        if self._rsa_pub is None:
            messagebox.showwarning("No key", "No RSA public key loaded")
            return
        path = filedialog.asksaveasfilename(defaultextension='.pem')
        if not path:
            return
        try:
            # write bytes depending on key object type
            if hasattr(self._rsa_pub, 'export_key'):
                data = self._rsa_pub.export_key()
            else:
                data = str(self._rsa_pub).encode()
            with open(path, 'wb') as f:
                f.write(data)
            messagebox.showinfo('Saved', f'Public key saved to\n{path}')
        except Exception as e:
            messagebox.showerror('Error', str(e))

    def export_rsa_private(self):
        if self._rsa_priv is None:
            messagebox.showwarning("No key", "No RSA private key loaded")
            return
        path = filedialog.asksaveasfilename(defaultextension='.pem')
        if not path:
            return
        try:
            if hasattr(self._rsa_priv, 'export_key'):
                data = self._rsa_priv.export_key()
            else:
                data = str(self._rsa_priv).encode()
            with open(path, 'wb') as f:
                f.write(data)
            messagebox.showinfo('Saved', f'Private key saved to\n{path}')
        except Exception as e:
            messagebox.showerror('Error', str(e))

    # ---------------------------------------------------------
    # THREAT ANALYSIS TAB
    # ---------------------------------------------------------
    def _build_threat_tab(self, parent):
        frame = tk.Frame(parent, bg=BG_DARK)
        tk.Label(frame, text="Threat Analysis Tools", fg=ACCENT, bg=BG_DARK, font=("Segoe UI", 16, "bold")).pack(pady=10)

        # Weak password
        tk.Label(frame, text="Check Weak Password", fg=TEXT_LIGHT, bg=BG_DARK).pack(pady=5)
        self.pass_entry = tk.Entry(frame, width=40, bg=BG_CARD, fg=TEXT_LIGHT, insertbackground="white")
        self.pass_entry.pack()
        tk.Button(frame, text="Analyze", bg=ACCENT, fg="black", command=self.check_password).pack(pady=5)

        # Hash risk
        tk.Label(frame, text="Check Hash Algorithm", fg=TEXT_LIGHT, bg=BG_DARK).pack(pady=15)
        self.hash_entry = tk.Entry(frame, width=40, bg=BG_CARD, fg=TEXT_LIGHT, insertbackground="white")
        self.hash_entry.pack()
        tk.Button(frame, text="Analyze", bg=ACCENT, fg="black", command=self.check_hash).pack(pady=5)

        self.threat_output = tk.Label(frame, text="", fg=GOOD, bg=BG_DARK, font=("Segoe UI", 12))
        self.threat_output.pack(pady=20)

        return frame

    def check_password(self):
        pw = self.pass_entry.get().strip()
        if is_weak_password(pw):
            self.threat_output.config(text="⚠ Weak password detected", fg=WARN)
        else:
            self.threat_output.config(text="✔ Strong password", fg=GOOD)

    def check_hash(self):
        name = self.hash_entry.get().strip()
        if is_hash_algorithm_weak(name):
            self.threat_output.config(text="⚠ Weak hash algorithm", fg=WARN)
        else:
            self.threat_output.config(text="✔ Safe hash algorithm", fg=GOOD)


# -------------------------------------------------------------
# RUN
# -------------------------------------------------------------
if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    app = CryptoGuardGUI(base)
    app.mainloop()
