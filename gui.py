# gui.py - FINAL CLEAN MASTERPIECE (No Key Management Tab)
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os

# YOUR FOLDER IS CALLED "cryptographys" → keep this import
from cryptographys import encrypt_text, decrypt_text, encrypt_file, decrypt_file

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CryptoGuardApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("CryptoGuard v1.0")
        self.root.geometry("900x720")
        self.root.configure(fg_color="#1f1f2e")
        self.create_widgets()

    def create_widgets(self):
        title = ctk.CTkLabel(self.root, text="CRYPTOGUARD", font=("Orbitron", 36, "bold"),
                             text_color="#00ff99")
        title.pack(pady=20)

        subtitle = ctk.CTkLabel(self.root, text="Learn Cryptography • Encrypt Safely • Analyze Threats",
                                font=("Consolas", 14), text_color="#888")
        subtitle.pack(pady=5)

        tabview = ctk.CTkTabview(self.root, width=850, height=520)
        tabview.pack(pady=20)

        # ONLY 3 TABS — CLEAN & PROFESSIONAL
        tabview.add("Text Encryption")
        tabview.add("File Encryption")
        tabview.add("Threat Analysis")

        self.build_text_tab(tabview)
        self.build_file_tab(tabview)
        self.build_threat_tab(tabview)

    def build_text_tab(self, tabview):
        frame = tabview.tab("Text Encryption")
        self.text_input = ctk.CTkTextbox(frame, width=760, height=180, font=("Consolas", 12))
        self.text_input.pack(pady=15)

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=10)

        ctk.CTkButton(btn_frame, text="Encrypt Text", fg_color="#00ff41", hover_color="#00cc33",
                      command=self.encrypt_text).grid(row=0, column=0, padx=15)
        ctk.CTkButton(btn_frame, text="Decrypt Text", fg_color="#ff2a6d", hover_color="#cc0044",
                      command=self.decrypt_text).grid(row=0, column=1, padx=15)

        self.text_result = ctk.CTkTextbox(frame, width=760, height=150, font=("Consolas", 11))
        self.text_result.pack(pady=15)

    def build_file_tab(self, tabview):
        frame = tabview.tab("File Encryption")
        ctk.CTkLabel(frame, text="Secure Your Files with Hybrid Encryption", font=("Arial", 16)).pack(pady=20)

        ctk.CTkButton(frame, text="Select File to Encrypt", fg_color="#05d6d9", hover_color="#03a9ac",
                      width=320, height=50, command=self.encrypt_file).pack(pady=12)
        ctk.CTkButton(frame, text="Select File to Decrypt", fg_color="#ff9100", hover_color="#cc7400",
                      width=320, height=50, command=self.decrypt_file).pack(pady=12)

        self.file_status = ctk.CTkLabel(frame, text="No file selected", text_color="#aaa")
        self.file_status.pack(pady=22)

        # 3 PERFECT FOLDER BUTTONS
        folder_frame = ctk.CTkFrame(frame, fg_color="transparent")
        folder_frame.pack(pady=10)

        ctk.CTkButton(folder_frame, text="Open Encrypted Folder", 
                      fg_color="#ff2a6d", hover_color="#cc0044", width=280, height=45,
                      command=self.open_encrypted_folder).pack(pady=8)
        ctk.CTkButton(folder_frame, text="Open Decrypted Folder", 
                      fg_color="#8a2be2", hover_color="#9932cc", width=280, height=45,
                      command=self.open_decrypted_folder).pack(pady=8)
        ctk.CTkButton(folder_frame, text="Open Keys Folder", 
                      fg_color="#00ff41", hover_color="#00cc33", width=280, height=45,
                      command=self.open_keys_folder).pack(pady=8)

    def build_threat_tab(self, tabview):
        frame = tabview.tab("Threat Analysis")
        ctk.CTkLabel(frame, text="Password Strength Analyzer", font=("Arial", 18, "bold"),
                     text_color="#00ffff").pack(pady=30)
        self.pw_entry = ctk.CTkEntry(frame, placeholder_text="Enter password to test", show="*", width=400)
        self.pw_entry.pack(pady=15)
        ctk.CTkButton(frame, text="Analyze Password", fg_color="#ff2a6d", hover_color="#cc0044",
                      command=self.analyze_password).pack(pady=12)
        self.pw_result = ctk.CTkLabel(frame, text="Result will appear here", font=("Consolas", 14),
                                      text_color="#888", height=120, wraplength=600)
        self.pw_result.pack(pady=20)

    # TEXT ENCRYPTION
    def encrypt_text(self):
        text = self.text_input.get("0.0", "end").strip()
        if not text:
            messagebox.showwarning("Empty", "Please enter text to encrypt!")
            return
        try:
            encrypted_b64, key_name = encrypt_text(text)
            self.text_result.delete("0.0", "end")
            self.text_result.insert("0.0", encrypted_b64)
            messagebox.showinfo("TEXT ENCRYPTED!", 
                f"New key generated!\n\nKey: {key_name}\nSaved: keys/{key_name}_private.pem\n\nKEEP THIS KEY SAFE!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{e}")

    def decrypt_text(self):
        text = self.text_input.get("0.0", "end").strip()
        if not text:
            messagebox.showwarning("Empty", "Paste encrypted text first!")
            return
        try:
            output_path = decrypt_text(text)
            self.text_result.delete("0.0", "end")
            self.text_result.insert("0.0", f"DECRYPTED & SAVED!\n→ {os.path.basename(output_path)}")
            messagebox.showinfo("TEXT DECRYPTED!", f"Saved to decrypted_folder/\n→ {os.path.basename(output_path)}")
            self.open_decrypted_folder()
        except Exception as e:
            messagebox.showerror("FAILED", f"Wrong key or corrupted data!\n\n{e}")

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path: return
        try:
            output_path, key_name = encrypt_file(file_path)
            self.file_status.configure(text=f"ENCRYPTED → {key_name}", text_color="#00ff99")
            messagebox.showinfo("FILE ENCRYPTED!", 
                f"Key: {key_name}\nFile: secured_files/{os.path.basename(output_path)}\n\nNEVER LOSE THIS KEY!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{e}")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(
            initialdir="secured_files",
            title="Select encrypted file (.cg_enc)",
            filetypes=[("CryptoGuard Files", "*.cg_enc")]
        )
        if not file_path: return
        try:
            output_path = decrypt_file(file_path)
            self.file_status.configure(text="DECRYPTED → decrypted_folder/", text_color="#05d6d9")
            messagebox.showinfo("DECRYPTED!", f"Saved to decrypted_folder/\n→ {os.path.basename(output_path)}")
            if messagebox.askyesno("Open Folder?", "Open decrypted_folder now?"):
                self.open_decrypted_folder()
        except Exception as e:
            messagebox.showerror("FAILED", str(e))

    # FOLDER OPENERS
    def open_encrypted_folder(self):
        self._open_folder("secured_files", "Encrypted Files")

    def open_decrypted_folder(self):
        self._open_folder("decrypted_folder", "Decrypted Files")

    def open_keys_folder(self):
        self._open_folder("keys", "Private Keys")

    def _open_folder(self, folder_name, title):
        folder = os.path.join(os.getcwd(), folder_name)
        os.makedirs(folder, exist_ok=True)
        import subprocess, platform
        try:
            if platform.system() == "Windows":
                os.startfile(folder)
            elif platform.system() == "Darwin":
                subprocess.run(["open", folder])
            else:
                subprocess.run(["xdg-open", folder])
        except:
            messagebox.showinfo(title, f"Location:\n{folder}")

    def analyze_password(self):
        pw = self.pw_entry.get()
        if not pw:
            self.pw_result.configure(text="Please enter a password!", text_color="#ff2a6d")
            return
        score = len(pw)*2 + (10 if any(c.isupper() for c in pw) else 0) + \
                (15 if any(c.isdigit() for c in pw) else 0) + (20 if any(c in "!@#$%^&*()" for c in pw) else 0)
        if score >= 55:   self.pw_result.configure(text="VERY STRONG!", text_color="#00ff99")
        elif score >= 40: self.pw_result.configure(text="Strong", text_color="#00ffff")
        elif score >= 25: self.pw_result.configure(text="Medium - Add symbols & numbers!", text_color="#ffff00")
        else:             self.pw_result.configure(text="WEAK - Too short!", text_color="#ff2a6d")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = CryptoGuardApp()
    app.run()