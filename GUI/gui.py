# gui.py - CryptoGuard v2.0 (2025 Secure Edition)
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os

# Correct imports from your updated secure modules
from cryptographys import encrypt_text, decrypt_text, encrypt_file, decrypt_file
from threat_analysis.password_strength import analyze_password_strength

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CryptoGuardApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("CryptoGuard v1.0 - Secure Encryption Suite")
        
        # Responsive window
        self.root.geometry("1100x750")
        self.root.minsize(900, 650)
        
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.create_widgets()

    def create_widgets(self):
        main_frame = ctk.CTkFrame(self.root, corner_radius=15, fg_color="#1a1a2e")
        main_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        # Title
        title = ctk.CTkLabel(main_frame, text="CRYPTOGUARD", 
                             font=("Orbitron", 48, "bold"), text_color="#00ff99")
        title.grid(row=0, column=0, pady=(30, 10))

        subtitle = ctk.CTkLabel(main_frame, text="Hybrid RSA-3072 + AES-256-GCM • Zero Fixed Folders • Maximum Security",
                                font=("Consolas", 16), text_color="#00ffff")
        subtitle.grid(row=1, column=0, pady=(0, 20))

        # Tabs
        tabview = ctk.CTkTabview(main_frame)
        tabview.grid(row=2, column=0, sticky="nsew", padx=30, pady=20)

        tabview.add("Text Encryption")
        tabview.add("File Encryption")
        tabview.add("Threat Analysis")

        self.build_text_tab(tabview)
        self.build_file_tab(tabview)
        self.build_threat_tab(tabview)

    def build_text_tab(self, tabview):
        frame = tabview.tab("Text Encryption")
        frame.grid_rowconfigure(0, weight=3)
        frame.grid_rowconfigure(2, weight=3)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Enter text to encrypt/decrypt", font=("Arial", 14), text_color="#aaa")\
            .grid(row=0, column=0, pady=(30, 5), sticky="n")

        self.text_input = ctk.CTkTextbox(frame, font=("Consolas", 13))
        self.text_input.grid(row=0, column=0, sticky="nsew", padx=40, pady=(0, 10))

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=1, column=0, pady=15)
        btn_frame.grid_columnconfigure((0,1), weight=1)

        ctk.CTkButton(btn_frame, text="ENCRYPT TEXT", fg_color="#0066ff", hover_color="#32d6ff",
                      font=("Arial", 14, "bold"), height=50, command=self.encrypt_text_action)\
                      .grid(row=0, column=0, padx=30, sticky="ew")

        ctk.CTkButton(btn_frame, text="DECRYPT FROM FILE", fg_color="#b523ef", hover_color="#c900cc",
                      font=("Arial", 14, "bold"), height=50, command=self.decrypt_text_action)\
                      .grid(row=0, column=1, padx=30, sticky="ew")

        ctk.CTkLabel(frame, text="Result / Encrypted Package (copy or save)", font=("Arial", 14), text_color="#aaa")\
            .grid(row=2, column=0, pady=(20, 5), sticky="n")

        self.text_result = ctk.CTkTextbox(frame, font=("Consolas", 12))
        self.text_result.grid(row=2, column=0, sticky="nsew", padx=40, pady=(0, 30))

    def build_file_tab(self, tabview):
        frame = tabview.tab("File Encryption")
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Secure File Encryption", 
                     font=("Arial", 24, "bold"), text_color="#05d6d9")\
                     .grid(row=0, column=0, pady=50)

        ctk.CTkButton(frame, text="ENCRYPT A FILE", fg_color="#00c3ff", hover_color="#0074cc",
                      font=("Arial", 18, "bold"), height=70, width=500, command=self.encrypt_file_action)\
                      .grid(row=1, column=0, pady=20)

        ctk.CTkButton(frame, text="DECRYPT A FILE", fg_color="#b42aff", hover_color="#b100cc",
                      font=("Arial", 18, "bold"), height=70, width=500, command=self.decrypt_file_action)\
                      .grid(row=2, column=0, pady=20)

        self.file_status = ctk.CTkLabel(frame, text="Ready to secure your files", 
                                        font=("Consolas", 18), text_color="#00ffff", wraplength=900)
        self.file_status.grid(row=3, column=0, pady=40)

    def build_threat_tab(self, tabview):
        frame = tabview.tab("Threat Analysis")
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Professional Password Strength Analyzer", 
                     font=("Arial", 22, "bold"), text_color="#00ffff")\
                     .grid(row=0, column=0, pady=50)

        self.pw_entry = ctk.CTkEntry(frame, placeholder_text="Type or paste password here", show="*", 
                                     font=("Consolas", 18), height=60, width=600)
        self.pw_entry.grid(row=1, column=0, pady=30)

        ctk.CTkButton(frame, text="ANALYZE STRENGTH", fg_color="#ff2a6d", hover_color="#cc0044",
                      font=("Arial", 18, "bold"), height=70, width=400, command=self.analyze_password)\
                      .grid(row=2, column=0, pady=30)

        self.pw_result = ctk.CTkLabel(frame, text="Enter a password to begin analysis", 
                                      font=("Consolas", 16), text_color="#888",
                                      wraplength=900, justify="center")
        self.pw_result.grid(row=3, column=0, pady=40, sticky="nsew")

    # === ACTION METHODS ===

    def encrypt_text_action(self):
        text = self.text_input.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showwarning("Empty Input", "Please enter some text to encrypt!")
            return
        try:
            encrypted_hex, enc_path, pub_path, priv_path = encrypt_text(text)
            self.text_result.delete("1.0", "end")
            self.text_result.insert("1.0", encrypted_hex)
            
            msg = (f"Text Encrypted Successfully!\n\n"
                   f"• Encrypted file saved to:\n{os.path.basename(enc_path)}\n\n"
                   f"• Public key: {os.path.basename(pub_path)}\n"
                   f"• Private key: {os.path.basename(priv_path)}\n\n"
                   f"KEEP YOUR PRIVATE KEY SAFE!")
            messagebox.showinfo("Encryption Complete", msg)
        except Exception as e:
            messagebox.showerror("Encryption Failed", str(e))

    def decrypt_text_action(self):
        try:
            output_path = decrypt_text()  # This opens file dialog internally
            self.text_result.delete("1.0", "end")
            self.text_result.insert("1.0", f"DECRYPTION SUCCESSFUL!\n\n"
                                            f"Decrypted text saved to:\n{output_path}")
            messagebox.showinfo("Decrypted!", f"File saved:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Decryption Failed", str(e))

    def encrypt_file_action(self):
        input_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not input_path:
            return
        try:
            enc_path, pub_path, priv_path = encrypt_file(input_path)
            self.file_status.configure(
                text=f"ENCRYPTED → {os.path.basename(enc_path)}", 
                text_color="#00ff99"
            )
            msg = (f"File Encrypted Successfully!\n\n"
                   f"• Encrypted: {os.path.basename(enc_path)}\n"
                   f"• Public Key: {os.path.basename(pub_path)}\n"
                   f"• Private Key: {os.path.basename(priv_path)}\n\n"
                   f"Store your private key securely!")
            messagebox.showinfo("Success", msg)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.file_status.configure(text="Encryption failed", text_color="#ff2a6d")

    def decrypt_file_action(self):
        try:
            output_path = decrypt_file()  # Opens dialogs internally
            self.file_status.configure(
                text=f"DECRYPTED → {os.path.basename(output_path)}", 
                text_color="#05d6d9"
            )
            messagebox.showinfo("Decryption Complete", f"File saved to:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Decryption Failed", str(e))
            self.file_status.configure(text="Decryption failed", text_color="#ff2a6d")

    def analyze_password(self):
        pw = self.pw_entry.get().strip()
        if not pw:
            self.pw_result.configure(text="⚠ Please enter a password!", text_color="#ff4444")
            return

        try:
            score, label, feedback, color = analyze_password_strength(pw)

            lines = [f"🔐 STRENGTH: {score}/100 → {label}", ""]
            lines.extend(f"• {item}" for item in feedback)
            result = "\n".join(lines)

            # Use brighter/more visible colors for weak/medium
            display_color = color
            if score < 50:
                display_color = "#ffaa00"  # Brighter orange for weak
            elif score < 70:
                display_color = "#ffff66"  # Brighter yellow

            self.pw_result.configure(
                text=result,
                text_color=display_color,
                font=("Consolas", 17, "bold")  # Slightly larger/bolder for visibility
            )

            # Flash effect for strong
            if score >= 80:
                self.pw_result.configure(text_color="#00ff88")
                self.root.after(500, lambda: self.pw_result.configure(text_color=display_color))

        except Exception as e:
            self.pw_result.configure(text=f"Error: {str(e)}", text_color="#ff0000")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = CryptoGuardApp()
    app.run()