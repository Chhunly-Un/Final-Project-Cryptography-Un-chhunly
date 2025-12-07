# gui.py - FINAL RESPONSIVE MASTERPIECE (100% Fixed & Beautiful)
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os

from cryptographys import encrypt_text, decrypt_text, encrypt_file, decrypt_file
from threat_analysis.password_strength import analyze_password_strength

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CryptoGuardApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("CryptoGuard v1.0")
        
        # RESPONSIVE WINDOW
        self.root.geometry("1100x750")
        self.root.minsize(900, 650)
        
        # Make everything stretch
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.create_widgets()

    def create_widgets(self):
        # MAIN FRAME - fills window
        main_frame = ctk.CTkFrame(self.root, corner_radius=15, fg_color="#1a1a2e")
        main_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        # TITLE
        title = ctk.CTkLabel(main_frame, text="CRYPTOGUARD", 
                             font=("Orbitron", 48, "bold"), text_color="#00ff99")
        title.grid(row=0, column=0, pady=(30, 10))

        subtitle = ctk.CTkLabel(main_frame, text="Learn • Encrypt • Analyze • Stay Secure",
                                font=("Consolas", 16), text_color="#00ffff")
        subtitle.grid(row=1, column=0, pady=(0, 20))

        # TABS - RESPONSIVE
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
        frame.grid_rowconfigure(1, weight=0)
        frame.grid_columnconfigure(0, weight=1)

        self.text_input = ctk.CTkTextbox(frame, font=("Consolas", 13))
        self.text_input.grid(row=0, column=0, sticky="nsew", padx=40, pady=(30, 10))

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=1, column=0, pady=15)
        btn_frame.grid_columnconfigure((0,1), weight=1)

        ctk.CTkButton(btn_frame, text="ENCRYPT TEXT", fg_color="#00ff41", hover_color="#00cc33",
                      font=("Arial", 14, "bold"), height=50, command=self.encrypt_text).grid(row=0, column=0, padx=20)
        ctk.CTkButton(btn_frame, text="DECRYPT TEXT", fg_color="#ff2a6d", hover_color="#cc0044",
                      font=("Arial", 14, "bold"), height=50, command=self.decrypt_text).grid(row=0, column=1, padx=20)

        self.text_result = ctk.CTkTextbox(frame, font=("Consolas", 12))
        self.text_result.grid(row=2, column=0, sticky="nsew", padx=40, pady=(10, 30))

    def build_file_tab(self, tabview):
        frame = tabview.tab("File Encryption")
        frame.grid_rowconfigure(4, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Secure Your Files with Hybrid RSA+AES-256", 
                     font=("Arial", 20, "bold"), text_color="#05d6d9").grid(row=0, column=0, pady=40)

        ctk.CTkButton(frame, text="Select File to ENCRYPT", fg_color="#05d6d9", hover_color="#03a9ac",
                      font=("Arial", 16, "bold"), height=60, width=400, command=self.encrypt_file).grid(row=1, column=0, pady=15)
        ctk.CTkButton(frame, text="Select File to DECRYPT", fg_color="#ff9100", hover_color="#cc7400",
                      font=("Arial", 16, "bold"), height=60, width=400, command=self.decrypt_file).grid(row=2, column=0, pady=15)

        self.file_status = ctk.CTkLabel(frame, text="Ready", font=("Consolas", 16), text_color="#00ff99")
        self.file_status.grid(row=3, column=0, pady=30)

        # FOLDER BUTTONS - PERFECT LAYOUT
        folder_frame = ctk.CTkFrame(frame, fg_color="transparent")
        folder_frame.grid(row=4, column=0, pady=20)
        folder_frame.grid_columnconfigure((0,1,2), weight=1)

        ctk.CTkButton(folder_frame, text="Open Encrypted Files", fg_color="#ff2a6d", hover_color="#cc0044",
                      font=("Arial", 14, "bold"), height=55, command=self.open_encrypted_folder).grid(row=0, column=0, padx=15)
        ctk.CTkButton(folder_frame, text="Open Decrypted Files", fg_color="#8a2be2", hover_color="#9932cc",
                      font=("Arial", 14, "bold"), height=55, command=self.open_decrypted_folder).grid(row=0, column=1, padx=15)
        ctk.CTkButton(folder_frame, text="Open Keys Folder", fg_color="#00ff41", hover_color="#00cc33",
                      font=("Arial", 14, "bold"), height=55, command=self.open_keys_folder).grid(row=0, column=2, padx=15)

    def build_threat_tab(self, tabview):
        frame = tabview.tab("Threat Analysis")
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Professional Password Strength Analyzer", 
                     font=("Arial", 22, "bold"), text_color="#00ffff").grid(row=0, column=0, pady=40)

        self.pw_entry = ctk.CTkEntry(frame, placeholder_text="Enter password to analyze", show="*", 
                                     font=("Consolas", 16), height=55, width=500)
        self.pw_entry.grid(row=1, column=0, pady=20)

        ctk.CTkButton(frame, text="ANALYZE PASSWORD", fg_color="#ff2a6d", hover_color="#cc0044",
                      font=("Arial", 18, "bold"), height=70, width=400, command=self.analyze_password).grid(row=2, column=0, pady=25)

        self.pw_result = ctk.CTkLabel(frame, text="Result will appear here", 
                                      font=("Consolas", 16), text_color="#888",
                                      wraplength=800, justify="center")
        self.pw_result.grid(row=3, column=0, pady=30, sticky="nsew")

    # YOUR FUNCTIONS (unchanged)
    def encrypt_text(self):
        text = self.text_input.get("0.0", "end").strip()
        if not text:
            messagebox.showwarning("Empty", "Please enter text!")
            return
        try:
            encrypted_b64, key_name, saved_path = encrypt_text(text)
            self.text_result.delete("0.0", "end")
            self.text_result.insert("0.0", encrypted_b64)
            messagebox.showinfo("SUCCESS", f"Encrypted & Saved!\n→ {os.path.basename(saved_path)}\nKey: {key_name}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text(self):
        text = self.text_input.get("0.0", "end").strip()
        if not text:
            messagebox.showwarning("Empty", "Paste encrypted text!")
            return
        try:
            output_path = decrypt_text(text)
            self.text_result.delete("0.0", "end")
            self.text_result.insert("0.0", f"DECRYPTED!\n→ {os.path.basename(output_path)}")
            messagebox.showinfo("SUCCESS", f"Decrypted!\n→ {os.path.basename(output_path)}")
            self.open_decrypted_folder()
        except Exception as e:
            messagebox.showerror("FAILED", str(e))

    def encrypt_file(self):
        path = filedialog.askopenfilename()
        if not path: return
        try:
            out, key = encrypt_file(path)
            self.file_status.configure(text=f"ENCRYPTED → {key}", text_color="#00ff99")
            messagebox.showinfo("SUCCESS", f"Encrypted!\n→ {os.path.basename(out)}\nKey: {key}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        path = filedialog.askopenfilename(initialdir="secured_files", filetypes=[("CG Files", "*.cg_enc")])
        if not path: return
        try:
            out = decrypt_file(path)
            self.file_status.configure(text="DECRYPTED → decrypted_folder/", text_color="#05d6d9")
            messagebox.showinfo("SUCCESS", f"Decrypted!\n→ {os.path.basename(out)}")
            if messagebox.askyesno("Open?", "Open folder?"):
                self.open_decrypted_folder()
        except Exception as e:
            messagebox.showerror("FAILED", str(e))

    def analyze_password(self):
        pw = self.pw_entry.get()
        if not pw:
            self.pw_result.configure(text="Enter a password!", text_color="#ff2a6d")
            return
        score, label, feedback, color = analyze_password_strength(pw)
        result = f"Score: {score}/100 → {label}\n\n" + "\n".join(f"• {f}" for f in feedback)
        self.pw_result.configure(text=result, text_color=color)

    def open_encrypted_folder(self): self._open("secured_files")
    def open_decrypted_folder(self): self._open("decrypted_folder")
    def open_keys_folder(self):      self._open("keys")

    def _open(self, folder):
        path = os.path.join(os.getcwd(), folder)
        os.makedirs(path, exist_ok=True)
        import subprocess, platform
        try:
            if platform.system() == "Windows":
                os.startfile(path)
            else:
                subprocess.run(["xdg-open", path] if platform.system() != "Darwin" else ["open", path])
        except:
            messagebox.showinfo("Folder", path)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = CryptoGuardApp()
    app.run()