# gui.py
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import platform
from PIL import Image, ImageTk
from cryptographys import encrypt_text, decrypt_text, encrypt_file, decrypt_file
from threat_analysis.password_strength import analyze_password_strength

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CryptoGuardApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("CryptoGuard v1.0 - Secure Encryption Suite with Digital Signatures")
        self.root.minsize(800, 600)
        self.root.geometry("900x700")

        # === CUSTOM ICON ===
        try:
            icon_path = "icons.ico"
            if os.path.exists(icon_path):
                self.root.after(300, lambda: self.root.iconbitmap(icon_path))
                print("Custom icon set successfully (delayed for Windows)!")
            else:
                print("icons.ico not found")
        except Exception as e:
            print(f"Icon error: {e}")

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.create_widgets()

    def create_widgets(self):
        main_frame = ctk.CTkFrame(self.root, corner_radius=0, fg_color="#1a1a2e")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        # Header
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(15, 5))
        header_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(header_frame, text="CRYPTOGUARD", font=("Orbitron", 40, "bold"), text_color="#00ff99")\
            .grid(row=0, column=0)
        ctk.CTkLabel(header_frame, text="Hybrid RSA-3072 + AES-256-GCM • Digital Signatures • Maximum Security",
                     font=("Consolas", 13), text_color="#00ffff")\
            .grid(row=1, column=0, pady=(0, 8))

        # Tabview
        self.tabview = ctk.CTkTabview(main_frame, corner_radius=12)
        self.tabview.grid(row=2, column=0, sticky="nsew", padx=15, pady=(0, 15))

        self.tabview.add("Text Encryption")
        self.tabview.add("File Encryption")
        self.tabview.add("Threat Analysis")

        self.build_text_tab()
        self.build_file_tab()
        self.build_threat_tab()

    def build_text_tab(self):
        frame = self.tabview.tab("Text Encryption")
        frame.grid_rowconfigure(0, weight=4)
        frame.grid_rowconfigure(2, weight=4)
        frame.grid_rowconfigure(1, weight=0)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Enter text to encrypt/decrypt", font=("Arial", 15), text_color="#ccc")\
            .grid(row=0, column=0, pady=(15, 8), sticky="n")

        self.text_input = ctk.CTkTextbox(frame, font=("Consolas", 13), wrap="word")
        self.text_input.grid(row=0, column=0, sticky="nsew", padx=35, pady=(0, 10))

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=1, column=0, pady=8, sticky="ew")
        btn_frame.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkButton(btn_frame, text="ENCRYPT TEXT", fg_color="#ff0000", hover_color="#ff4444",
                      font=("Arial", 15, "bold"), height=50, command=self.encrypt_text_action)\
                      .grid(row=0, column=0, padx=35, sticky="ew")
        ctk.CTkButton(btn_frame, text="DECRYPT FROM FILE", fg_color="#2a7fff", hover_color="#5a9fff",
                      font=("Arial", 15, "bold"), height=50, command=self.decrypt_text_action)\
                      .grid(row=0, column=1, padx=35, sticky="ew")

        self.sign_text_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(btn_frame, text="✔ Include digital signature (recommended)",
                        variable=self.sign_text_var, font=("Arial", 13), text_color="#00ffaa")\
                        .grid(row=1, column=0, columnspan=2, pady=8)

        ctk.CTkLabel(frame, text="Result / Encrypted Package", font=("Arial", 15), text_color="#ccc")\
            .grid(row=2, column=0, pady=(12, 8), sticky="n")

        self.text_result = ctk.CTkTextbox(frame, font=("Consolas", 12))
        self.text_result.grid(row=2, column=0, sticky="nsew", padx=35, pady=(0, 25))

    def build_file_tab(self):
        frame = self.tabview.tab("File Encryption")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_rowconfigure(4, weight=0)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Secure File Encryption", font=("Arial", 24, "bold"), text_color="#05d6d9")\
            .grid(row=0, column=0, pady=(30, 25))

        ctk.CTkButton(frame, text="ENCRYPT A FILE", fg_color="#ff0000", hover_color="#cc0000",
                      font=("Arial", 17, "bold"), height=65, command=self.encrypt_file_action)\
                      .grid(row=1, column=0, pady=12, padx=120, sticky="ew")
        ctk.CTkButton(frame, text="DECRYPT A FILE", fg_color="#2a5cff", hover_color="#3a7cff",
                      font=("Arial", 17, "bold"), height=65, command=self.decrypt_file_action)\
                      .grid(row=2, column=0, pady=12, padx=120, sticky="ew")

        self.sign_file_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(frame, text="✔ Include digital signature (recommended)",
                        variable=self.sign_file_var, font=("Arial", 14), text_color="#00ffaa")\
                        .grid(row=3, column=0, pady=8)

        self.file_status = ctk.CTkLabel(frame, text="Ready to secure your files",
                                        font=("Consolas", 17), text_color="#00ffff")
        self.file_status.grid(row=4, column=0, pady=20)

    def build_threat_tab(self):
        frame = self.tabview.tab("Threat Analysis")

        # Two rows: controls (fixed) + result (expands + scrollable)
        frame.grid_rowconfigure(0, weight=0)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Controls (compact)
        controls = ctk.CTkFrame(frame, fg_color="transparent")
        controls.grid(row=0, column=0, sticky="ew", pady=(10, 5))
        controls.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(controls, text="Professional Password Strength Analyzer",
                     font=("Arial", 20, "bold"), text_color="#00ffff")\
            .grid(row=0, column=0, pady=(5, 15))

        self.pw_entry = ctk.CTkEntry(controls, placeholder_text="Type or paste password here", show="*",
                                     font=("Consolas", 16), height=50)
        self.pw_entry.grid(row=1, column=0, pady=(0, 15), padx=80, sticky="ew")

        ctk.CTkButton(controls, text="ANALYZE STRENGTH",
                      fg_color="#ff2a6d", hover_color="#ff5a9d",
                      font=("Arial", 16, "bold"), height=60, width=320,
                      command=self.analyze_password)\
            .grid(row=2, column=0, pady=(0, 20))

        # Result box - scrollable and always visible
        self.pw_result = ctk.CTkTextbox(frame, font=("Consolas", 15), wrap="word",
                                        fg_color="#0f0f1e", border_width=2, corner_radius=12)
        self.pw_result.grid(row=1, column=0, sticky="nsew", padx=40, pady=(0, 30))
        self.pw_result.insert("1.0", "Enter a password above and click 'ANALYZE STRENGTH' to see the analysis here.\n\n"
                                    "This box is always visible and will scroll if the result is long.")
        self.pw_result.configure(state="disabled", text_color="#cccccc")

    def analyze_password(self):
        pw = self.pw_entry.get().strip()
        if not pw:
            self.update_result_text("⚠ Please enter a password to analyze!", "#ff6666")
            return
        try:
            score, label, feedback, color = analyze_password_strength(pw)
            lines = [f"🔐 STRENGTH: {score}/100 → {label}\n\n"]
            lines.extend(f"• {item}\n" for item in feedback)
            result = "".join(lines)
            display_color = "#ffaa00" if score < 70 else color
            self.update_result_text(result, display_color)
        except Exception as e:
            self.update_result_text(f"Error: {str(e)}", "#ff0000")

    def update_result_text(self, text, color):
        self.pw_result.configure(state="normal")
        self.pw_result.delete("1.0", "end")
        self.pw_result.insert("1.0", text)
        self.pw_result.configure(text_color=color)
        self.pw_result.configure(state="disabled")

    # Other actions (unchanged for brevity)
    def encrypt_text_action(self):
        text = self.text_input.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showwarning("Empty Input", "Please enter some text!")
            return
        try:
            encrypted_json, enc_path, pub_path, priv_path = encrypt_text(text, sign=self.sign_text_var.get())
            self.text_result.delete("1.0", "end")
            self.text_result.insert("1.0", encrypted_json)
            messagebox.showinfo("Success", "Text encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text_action(self):
        try:
            output_path = decrypt_text()
            self.text_result.delete("1.0", "end")
            self.text_result.insert("1.0", f"DECRYPTION SUCCESSFUL!\n\nSaved to:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def encrypt_file_action(self):
        input_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not input_path: return
        try:
            enc_path, pub_path, priv_path = encrypt_file(input_path, sign=self.sign_file_var.get())
            self.file_status.configure(text=f"ENCRYPTED → {os.path.basename(enc_path)}", text_color="#00ff99")
            messagebox.showinfo("Success", "File encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file_action(self):
        try:
            output_path = decrypt_file()
            self.file_status.configure(text=f"DECRYPTED → {os.path.basename(output_path)}", text_color="#05d6d9")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = CryptoGuardApp()
    app.run()