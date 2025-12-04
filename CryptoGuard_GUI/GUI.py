# gui.py
import sys
import json
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QPlainTextEdit, QLabel, QLineEdit, QFileDialog,
    QTabWidget, QMessageBox, QComboBox, QFormLayout, QSpinBox
)
from PyQt5.QtCore import Qt
from crypto_utils import (
    generate_aes_key, aes_encrypt_bytes, aes_decrypt_bytes,
    generate_rsa, rsa_encrypt_bytes, rsa_decrypt_bytes,
    hash_sha256_bytes, hash_sha3_bytes, hash_blake2b_bytes
)
from threat_engine import analyze_rsa_size, analyze_aes_length, analyze_password
from key_manager import save_keystore, load_keystore, KEYSTORE_PATH
from dashboard import compute_risk, export_risk_plot
from db import log_event

STORAGE_DIR = Path.home() / ".crypto_guard_plus"
STORAGE_DIR.mkdir(exist_ok=True)

def format_bytes_for_display(b):
    try:
        return b.decode('utf-8')
    except Exception:
        return b.hex()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptoGuard Plus")
        self.resize(1000, 700)
        self._build_ui()

    def _build_ui(self):
        tabs = QTabWidget()
        tabs.addTab(self._encrypt_tab_ui(), "Encrypt / Decrypt")
        tabs.addTab(self._keygen_tab_ui(), "Key Generator")
        tabs.addTab(self._hash_tab_ui(), "Hashing Tools")
        tabs.addTab(self._password_tab_ui(), "Password Analyzer")
        tabs.addTab(self._threat_tab_ui(), "Threat Analysis")
        tabs.addTab(self._dashboard_tab_ui(), "Dashboard")
        tabs.addTab(self._about_tab_ui(), "About")
        self.setCentralWidget(tabs)

    # Encrypt/Decrypt
    def _encrypt_tab_ui(self):
        page = QWidget()
        layout = QVBoxLayout()

        self.input_text = QPlainTextEdit()
        layout.addWidget(self.input_text)

        controls = QHBoxLayout()
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["AES-256 (Symmetric)", "RSA-2048 (Asymmetric)"])
        controls.addWidget(self.algo_combo)

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Paste key or leave blank to auto-generate")
        controls.addWidget(self.key_input)

        gen_btn = QPushButton("Generate Key")
        gen_btn.clicked.connect(self._generate_key_for_encrypt)
        controls.addWidget(gen_btn)

        layout.addLayout(controls)

        actions = QHBoxLayout()
        enc_btn = QPushButton("Encrypt")
        enc_btn.clicked.connect(self._do_encrypt)
        dec_btn = QPushButton("Decrypt")
        dec_btn.clicked.connect(self._do_decrypt)
        actions.addWidget(enc_btn)
        actions.addWidget(dec_btn)
        layout.addLayout(actions)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        save_btn = QPushButton("Save Output")
        save_btn.clicked.connect(self._save_output)
        layout.addWidget(save_btn)

        page.setLayout(layout)
        return page

    def _generate_key_for_encrypt(self):
        algo = self.algo_combo.currentText()
        if "AES" in algo:
            key = generate_aes_key()
            self.key_input.setText(key.hex())
        else:
            priv, pub = generate_rsa(2048)
            # save to keystore temporarily?
            self.key_input.setText(pub.decode())
            # also write private to file for convenience (user can save)
            p = STORAGE_DIR / "rsa_private.pem"
            p.write_bytes(priv)
            QMessageBox.information(self, "RSA", f"RSA keys generated. Private saved to {p}")

    def _do_encrypt(self):
        algo = self.algo_combo.currentText()
        txt = self.input_text.toPlainText()
        if not txt:
            QMessageBox.warning(self, "Input", "Provide input to encrypt")
            return
        plaintext = txt.encode('utf-8')
        if "AES" in algo:
            key_hex = self.key_input.text().strip()
            if key_hex:
                try:
                    key = bytes.fromhex(key_hex)
                except Exception:
                    QMessageBox.warning(self, "Key", "AES key must be hex")
                    return
            else:
                key = generate_aes_key()
                self.key_input.setText(key.hex())
            nonce, ciphertext, tag = aes_encrypt_bytes(plaintext, key)
            package = {"mode": "aes-eax", "nonce": nonce.hex(), "tag": tag.hex(), "ciphertext": ciphertext.hex()}
            self.output.setPlainText(json.dumps(package, indent=2))
            log_event("encrypt_aes", "AES encryption performed")
        else:
            pub_pem = self.key_input.text().strip().encode()
            try:
                ciphertext = rsa_encrypt_bytes(plaintext, pub_pem)
                self.output.setPlainText(ciphertext.hex())
                log_event("encrypt_rsa", "RSA encryption performed")
            except Exception as e:
                QMessageBox.warning(self, "RSA Error", str(e))

    def _do_decrypt(self):
        algo = self.algo_combo.currentText()
        txt = self.input_text.toPlainText().strip()
        if not txt:
            QMessageBox.warning(self, "Input", "Provide ciphertext to decrypt")
            return
        if "AES" in algo:
            key_hex = self.key_input.text().strip()
            if not key_hex:
                QMessageBox.warning(self, "Key", "Provide AES key (hex) to decrypt")
                return
            try:
                key = bytes.fromhex(key_hex)
            except Exception:
                QMessageBox.warning(self, "Key", "AES key must be hex")
                return
            try:
                package = json.loads(txt)
                nonce = bytes.fromhex(package['nonce'])
                tag = bytes.fromhex(package['tag'])
                ciphertext = bytes.fromhex(package['ciphertext'])
                plaintext = aes_decrypt_bytes(nonce, ciphertext, tag, key)
                self.output.setPlainText(format_bytes_for_display(plaintext))
                log_event("decrypt_aes", "AES decrypt")
            except Exception as e:
                QMessageBox.warning(self, "Decrypt", str(e))
        else:
            priv_pem = self.key_input.text().strip().encode()
            if not priv_pem:
                QMessageBox.warning(self, "Key", "Provide RSA private key (PEM) to decrypt")
                return
            try:
                ciphertext = bytes.fromhex(txt)
                plaintext = rsa_decrypt_bytes(ciphertext, priv_pem)
                self.output.setPlainText(format_bytes_for_display(plaintext))
                log_event("decrypt_rsa", "RSA decrypt")
            except Exception as e:
                QMessageBox.warning(self, "RSA Error", str(e))

    def _save_output(self):
        txt = self.output.toPlainText()
        if not txt:
            QMessageBox.warning(self, "Output", "Nothing to save")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save output")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(txt)
            QMessageBox.information(self, "Saved", f"Saved to {path}")

    # Key Generator Tab
    def _keygen_tab_ui(self):
        page = QWidget()
        layout = QVBoxLayout()
        form = QFormLayout()

        self.key_type = QComboBox()
        self.key_type.addItems(["AES-256", "RSA-2048"])
        form.addRow("Key Type:", self.key_type)

        self.rsa_bits = QSpinBox()
        self.rsa_bits.setRange(1024, 8192)
        self.rsa_bits.setValue(2048)
        form.addRow("RSA bits:", self.rsa_bits)

        gen_btn = QPushButton("Generate")
        gen_btn.clicked.connect(self._generate_key)
        form.addRow(gen_btn)

        layout.addLayout(form)
        self.key_display = QPlainTextEdit()
        layout.addWidget(self.key_display)

        save_btn = QPushButton("Save Keyfile")
        save_btn.clicked.connect(self._save_keyfile)
        layout.addWidget(save_btn)
        page.setLayout(layout)
        return page

    def _generate_key(self):
        typ = self.key_type.currentText()
        if "AES" in typ:
            key = generate_aes_key()
            self.key_display.setPlainText(f"AES-256 (hex):\n{key.hex()}")
        else:
            bits = int(self.rsa_bits.value())
            priv, pub = generate_rsa(bits)
            self.key_display.setPlainText(f"--- PRIVATE ---\n{priv.decode()}\n--- PUBLIC ---\n{pub.decode()}")

    def _save_keyfile(self):
        txt = self.key_display.toPlainText()
        if not txt:
            QMessageBox.warning(self, "No key", "Generate a key first")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save key file")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(txt)
            QMessageBox.information(self, "Saved", f"Saved to {path}")

    # Hashing Tab
    def _hash_tab_ui(self):
        page = QWidget()
        layout = QVBoxLayout()
        self.hash_input = QPlainTextEdit()
        layout.addWidget(self.hash_input)

        controls = QHBoxLayout()
        self.hash_combo = QComboBox()
        self.hash_combo.addItems(["SHA-256", "SHA3-256", "BLAKE2b"])
        controls.addWidget(self.hash_combo)
        gen_btn = QPushButton("Generate Hash")
        gen_btn.clicked.connect(self._generate_hash)
        controls.addWidget(gen_btn)
        layout.addLayout(controls)

        self.hash_output = QPlainTextEdit()
        self.hash_output.setReadOnly(True)
        layout.addWidget(self.hash_output)
        page.setLayout(layout)
        return page

    def _generate_hash(self):
        data = self.hash_input.toPlainText().encode('utf-8')
        algo = self.hash_combo.currentText()
        if algo == "SHA-256":
            out = hash_sha256_bytes(data)
        elif algo == "SHA3-256":
            out = hash_sha3_bytes(data)
        else:
            out = hash_blake2b_bytes(data)
        self.hash_output.setPlainText(out)
        log_event("hash", f"{algo} generated")

    # Password Analyzer Tab
    def _password_tab_ui(self):
        page = QWidget()
        layout = QVBoxLayout()
        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.pw_input)
        analyze_btn = QPushButton("Analyze Password")
        analyze_btn.clicked.connect(self._analyze_password)
        layout.addWidget(analyze_btn)
        self.pw_output = QPlainTextEdit()
        self.pw_output.setReadOnly(True)
        layout.addWidget(self.pw_output)
        return page

    def _analyze_password(self):
        pw = self.pw_input.text()
        if not pw:
            QMessageBox.warning(self, "Password", "Enter a password")
            return
        res = analyze_password(pw)
        lines = [f"Score: {res['score']}", f"Estimated entropy: {res['entropy']}"] + res["findings"]
        self.pw_output.setPlainText("\n".join(lines))
        log_event("pw_analyze", "Password analyzed")

    # Threat Analysis Tab
    def _threat_tab_ui(self):
        page = QWidget()
        layout = QVBoxLayout()
        self.rsa_check = QSpinBox()
        self.rsa_check.setRange(512, 8192)
        self.rsa_check.setValue(2048)
        layout.addWidget(QLabel("RSA bits to check:"))
        layout.addWidget(self.rsa_check)

        self.aes_len = QSpinBox()
        self.aes_len.setRange(1,64)
        self.aes_len.setValue(32)
        layout.addWidget(QLabel("AES key length (bytes):"))
        layout.addWidget(self.aes_len)

        run_btn = QPushButton("Analyze")
        run_btn.clicked.connect(self._run_threat_analysis)
        layout.addWidget(run_btn)

        self.threat_out = QPlainTextEdit()
        self.threat_out.setReadOnly(True)
        layout.addWidget(self.threat_out)
        return page

    def _run_threat_analysis(self):
        rsa_bits = self.rsa_check.value()
        aes_len = self.aes_len.value()
        findings = []
        findings += analyze_rsa_size(rsa_bits)
        findings += analyze_aes_length(aes_len)
        self.threat_out.setPlainText("\n".join(findings))
        log_event("threat_analysis", f"rsa={rsa_bits}, aes_bytes={aes_len}")

    # Dashboard Tab
    def _dashboard_tab_ui(self):
        page = QWidget()
        layout = QVBoxLayout()
        form = QHBoxLayout()

        self.db_rsa_ok = QComboBox()
        self.db_rsa_ok.addItems(["True","False"])
        form.addWidget(QLabel("RSA OK:"))
        form.addWidget(self.db_rsa_ok)

        self.db_aes_ok = QComboBox()
        self.db_aes_ok.addItems(["True","False"])
        form.addWidget(QLabel("AES OK:"))
        form.addWidget(self.db_aes_ok)

        self.db_pw_entropy = QComboBox()
        self.db_pw_entropy.addItems(["High","Medium","Low"])
        form.addWidget(QLabel("Password Entropy:"))
        form.addWidget(self.db_pw_entropy)

        compute_btn = QPushButton("Compute Risk & Export Plot")
        compute_btn.clicked.connect(self._compute_dashboard)
        form.addWidget(compute_btn)

        layout.addLayout(form)
        self.dashboard_label = QPlainTextEdit()
        self.dashboard_label.setReadOnly(True)
        layout.addWidget(self.dashboard_label)
        page.setLayout(layout)
        return page

    def _compute_dashboard(self):
        rsa_ok = self.db_rsa_ok.currentText() == "True"
        aes_ok = self.db_aes_ok.currentText() == "True"
        pw_entropy = self.db_pw_entropy.currentText()
        score = compute_risk(rsa_ok, aes_ok, pw_entropy)
        plot_path = export_risk_plot(score)
        self.dashboard_label.setPlainText(f"Risk Score: {score}\nPlot exported to: {plot_path}")
        log_event("dashboard", f"score={score}")

    def _about_tab_ui(self):
        page = QWidget()
        layout = QVBoxLayout()
        about = QPlainTextEdit()
        about.setReadOnly(True)
        about.setPlainText("CryptoGuard Plus\nA modular applied-cryptography demo.\nAuthor: UN Chhunly\nAttack Simulator removed by request.")
        layout.addWidget(about)
        page.setLayout(layout)
        return page

def launch_app():
    app = QApplication(sys.argv)
    mw = MainWindow()
    mw.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    launch_app()
