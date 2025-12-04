import json
from tkinter import Tk, Frame, Label, Button, Text, Entry, END, filedialog, messagebox, ttk
from crypto_engine import generate_aes_key, aes_encrypt_bytes, aes_decrypt_bytes, generate_rsa_keypair, serialize_private_key, serialize_public_key, load_private_key, load_public_key
from key_manager import encrypt_key_blob, decrypt_key_blob, save_blob_to_file, load_blob_from_file, KEYS_DIR
from threat_analysis import password_strength_feedback, hash_collision_warning, estimate_password_entropy

class CryptoGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('CryptoGuard')
        self.root.geometry('1000x700')
        self.current_aes_key = None
        self.build_ui()

    def build_ui(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill='both', expand=True)
        self.tab_enc = Frame(nb); self.tab_keys = Frame(nb)
        self.tab_pw = Frame(nb); self.tab_threat = Frame(nb)
        nb.add(self.tab_enc, text='Encrypt / Decrypt'); nb.add(self.tab_keys, text='Key Management')
        nb.add(self.tab_pw, text='Password Analyzer'); nb.add(self.tab_threat, text='Threat Analysis')
        self.build_enc_tab(); self.build_keys_tab(); self.build_pw_tab(); self.build_threat_tab()

    def build_enc_tab(self):
        f = self.tab_enc
        Label(f, text='Plaintext:').pack(anchor='w', padx=8, pady=4)
        self.text_plain = Text(f, height=10); self.text_plain.pack(fill='x', padx=8)
        btn_frame = Frame(f); btn_frame.pack(fill='x', padx=8, pady=6)
        Button(btn_frame, text='Load File', command=self.load_file_into_text).pack(side='left', padx=4)
        Button(btn_frame, text='Generate AES Key', command=self.ui_generate_aes_key).pack(side='left', padx=4)
        Button(btn_frame, text='Encrypt (AES)', command=self.ui_encrypt_text).pack(side='left', padx=4)
        Button(btn_frame, text='Decrypt (AES)', command=self.ui_decrypt_text).pack(side='left', padx=4)
        Label(f, text='Ciphertext (JSON):').pack(anchor='w', padx=8, pady=4)
        self.text_cipher = Text(f, height=10); self.text_cipher.pack(fill='x', padx=8)

    def load_file_into_text(self):
        p = filedialog.askopenfilename()
        if not p: return
        with open(p, 'rb') as f: data = f.read()
        try:
            text = data.decode('utf-8')
        except:
            text = '<binary: base64>\\n' + base64.b64encode(data).decode('utf-8')
        self.text_plain.delete('1.0', END); self.text_plain.insert(END, text)

    def ui_generate_aes_key(self):
        self.current_aes_key = generate_aes_key()
        messagebox.showinfo('AES Key', 'AES-256 key generated in memory.')

    def ui_encrypt_text(self):
        pt = self.text_plain.get('1.0', END).encode('utf-8')
        if not pt.strip(): messagebox.showwarning('Missing', 'Enter plaintext'); return
        if not self.current_aes_key: messagebox.showwarning('Missing key', 'Generate or load AES key'); return
        blob = aes_encrypt_bytes(self.current_aes_key, pt)
        self.text_cipher.delete('1.0', END); self.text_cipher.insert(END, json.dumps(blob))

    def ui_decrypt_text(self):
        try:
            blob = json.loads(self.text_cipher.get('1.0', END))
        except:
            messagebox.showerror('Bad', 'Ciphertext must be JSON'); return
        if not self.current_aes_key: messagebox.showwarning('No key', 'Generate or load AES key'); return
        try:
            pt = aes_decrypt_bytes(self.current_aes_key, blob)
            try: self.text_plain.delete('1.0', END); self.text_plain.insert(END, pt.decode('utf-8'))
            except: self.text_plain.delete('1.0', END); self.text_plain.insert(END, '<binary>'); 
        except Exception as e:
            messagebox.showerror('Decrypt failed', str(e))

    def build_keys_tab(self):
        f = self.tab_keys
        Label(f, text='AES Key Management:').pack(anchor='w', padx=8, pady=4)
        Button(f, text='Save current AES key (password protect)', command=self.ui_save_current_aes_key).pack(anchor='w', padx=8, pady=2)
        Button(f, text='Load AES key', command=self.ui_load_aes_key).pack(anchor='w', padx=8, pady=2)
        Label(f, text='RSA Key Management:').pack(anchor='w', padx=8, pady=8)
        Button(f, text='Generate RSA Keypair', command=self.ui_generate_rsa).pack(anchor='w', padx=8, pady=2)
        Button(f, text='Load RSA Private Key', command=self.ui_load_rsa_private).pack(anchor='w', padx=8, pady=2)
        Button(f, text='Load RSA Public Key', command=self.ui_load_rsa_public).pack(anchor='w', padx=8, pady=2)
        self.keys_list = Text(f, height=12); self.keys_list.pack(fill='both', padx=8, pady=8)
        self.refresh_keys_list()

    def ui_save_current_aes_key(self):
        if not self.current_aes_key: messagebox.showwarning('No key','Generate one first'); return
        name = filedialog.asksaveasfilename(initialdir=str(KEYS_DIR), defaultextension='.key')
        if not name: return
        import tkinter.simpledialog as sd
        pwd = sd.askstring('Master password','Enter a password to protect the AES key', show='*')
        if pwd is None: return
        blob = encrypt_key_blob(self.current_aes_key, pwd)
        save_blob_to_file(blob, name)
        messagebox.showinfo('Saved', f'AES key saved to {name}')
        self.refresh_keys_list()

    def ui_load_aes_key(self):
        p = filedialog.askopenfilename(initialdir=str(KEYS_DIR))
        if not p: return
        import tkinter.simpledialog as sd
        pwd = sd.askstring('Password','Enter password to unlock', show='*')
        if pwd is None: return
        try:
            blob = load_blob_from_file(p)
            key = decrypt_key_blob(blob, pwd)
            self.current_aes_key = key
            messagebox.showinfo('Loaded', 'AES key loaded into memory')
        except Exception as e:
            messagebox.showerror('Failed', str(e))

    def ui_generate_rsa(self):
        priv, pub = generate_rsa_keypair(2048)
        p = filedialog.asksaveasfilename(initialdir=str(KEYS_DIR), defaultextension='.pem')
        if not p: return
        with open(p, 'wb') as f: f.write(serialize_private_key(priv))
        with open(p + '.pub', 'wb') as f: f.write(serialize_public_key(pub))
        messagebox.showinfo('RSA', f'Private saved to {p} and public to {p}.pub')
        self.refresh_keys_list()

    def ui_load_rsa_private(self):
        p = filedialog.askopenfilename(initialdir=str(KEYS_DIR))
        if not p: return
        try:
            with open(p, 'rb') as f: data = f.read()
            key = load_private_key(data)
            size = getattr(key, 'key_size', 'unknown')
            messagebox.showinfo('Loaded', f'Private key size: {size}')
        except Exception as e:
            messagebox.showerror('Fail', str(e))

    def ui_load_rsa_public(self):
        p = filedialog.askopenfilename(initialdir=str(KEYS_DIR))
        if not p: return
        try:
            with open(p, 'rb') as f: data = f.read()
            key = load_public_key(data)
            size = getattr(key, 'key_size', 'unknown')
            messagebox.showinfo('Loaded', f'Public key size: {size}')
        except Exception as e:
            messagebox.showerror('Fail', str(e))

    def refresh_keys_list(self):
        import os
        self.keys_list.delete('1.0', END)
        files = sorted([f for f in (str(KEYS_DIR)).split('/') and __import__('os').listdir(KEYS_DIR) or []])
        # simple cross-platform: list files directly
        try:
            items = __import__('os').listdir(KEYS_DIR)
            for it in items:
                self.keys_list.insert(END, it + '\\n')
        except Exception:
            self.keys_list.insert(END, 'Unable to list keys dir')

    def build_pw_tab(self):
        f = self.tab_pw
        Label(f, text='Password Analyzer').pack(anchor='w', padx=8, pady=6)
        entry = Entry(f, show='*', width=60); entry.pack(padx=8, anchor='w')
        result = Label(f, text='', justify='left'); result.pack(padx=8, pady=8, anchor='w')
        def go():
            pw = entry.get()
            if not pw: messagebox.showwarning('Enter', 'Enter a password'); return
            res = password_strength_feedback(pw)
            txt = f'Entropy: {res["entropy"]:.1f} bits\\n'
            if res['issues']:
                txt += 'Issues:\\n' + '\\n'.join(['- ' + i for i in res['issues']])
            else:
                txt += 'No major issues.'
            result.config(text=txt)
        Button(f, text='Analyze', command=go).pack(padx=8, pady=4)

    def build_threat_tab(self):
        f = self.tab_threat
        Label(f, text='Threat Analysis').pack(anchor='w', padx=8, pady=6)
        self.threat_text = Text(f, height=20); self.threat_text.pack(fill='both', padx=8, pady=8)
        Button(f, text='Run Analysis', command=self.run_threat_analysis).pack(padx=8, pady=4)

    def run_threat_analysis(self):
        self.threat_text.delete('1.0', END)
        if not self.current_aes_key:
            self.threat_text.insert(END, 'AES key in memory: NOT LOADED\\n\\n')
        else:
            self.threat_text.insert(END, 'AES key in memory: OK\\n\\n')
        try:
            import os
            for f in sorted(__import__('os').listdir(KEYS_DIR)):
                self.threat_text.insert(END, f'File: {f}\\n')
                if f.endswith('.pem'):
                    try:
                        with open(KEYS_DIR / f, 'rb') as fh:
                            from crypto_engine import load_private_key
                            key = load_private_key(fh.read())
                            size = getattr(key, 'key_size', 0)
                            if size and size < 2048:
                                self.threat_text.insert(END, f'  Weak RSA key: {size} bits (recommend >= 2048)\\n\\n')
                            else:
                                self.threat_text.insert(END, f'  RSA key: {size} bits\\n\\n')
                    except Exception:
                        self.threat_text.insert(END, '  Could not parse PEM\\n\\n')
                elif f.endswith('.key'):
                    self.threat_text.insert(END, '  AES key blob (password protected)\\n\\n')
                else:
                    self.threat_text.insert(END, '  Unknown file type\\n\\n')
        except Exception as e:
            self.threat_text.insert(END, 'Failed to scan keys directory: ' + str(e))