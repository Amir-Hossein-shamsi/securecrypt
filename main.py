import os
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread, QSettings
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
    QHBoxLayout, QLineEdit, QPushButton, QFileDialog, QButtonGroup,
    QRadioButton, QMessageBox, QFormLayout, QProgressBar, QLabel
)
import sys, os

def resource_path(rel_path):
    """
    Get absolute path to resource, works for dev and for PyInstaller one‑file bundles.
    """
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller bundles everything in a temp dir
        base = sys._MEIPASS
    else:
        # running in normal Python
        base = os.path.abspath(".")
    return os.path.join(base, rel_path)
# Settings
CHUNK_SIZE = 1024 * 1024 * 4  # 4MB chunks
PBKDF2_ITERATIONS = 150000
CIPHER_MODE = modes.CTR
HEADER_SIZE = 1 + 256 + 1 + 16 + 16  # ext_len + ext + is_dir + salt + nonce

class EncryptionWorker(QObject):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    _cancel_requested = False

    def __init__(self, input_path, output_path, password, is_directory):
        super().__init__()
        self.input_path = input_path
        self.output_path = output_path
        self.password = password
        self.is_directory = is_directory

    def cancel(self):
        self._cancel_requested = True

    def run(self):
        try:
            if self.is_directory:
                self._process_directory()
            else:
                self._process_file()
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))
            if os.path.exists(self.output_path):
                os.remove(self.output_path)

    def _process_directory(self):
        zip_path = f"{self.input_path}.tmpzip"
        try:
            self.status.emit("Zipping directory...")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_STORED) as zipf:
                files = []
                for root, _, filenames in os.walk(self.input_path):
                    files.extend(os.path.join(root, f) for f in filenames)

                total_files = max(len(files), 1)
                for i, file in enumerate(files):
                    if self._cancel_requested: return
                    zipf.write(file, os.path.relpath(file, self.input_path))
                    self.progress.emit(int((i + 1) / total_files * 40))

            self._process_file(zip_path, is_directory=True)
        finally:
            if os.path.exists(zip_path):
                os.remove(zip_path)

    def _process_file(self, src_path=None, is_directory=False):
        src_path = src_path or self.input_path
        try:
            self.status.emit("Encrypting...")
            original_ext = '.zip' if is_directory else os.path.splitext(src_path)[1]
            ext_bytes = original_ext.encode('utf-8')
            ext_length = len(ext_bytes)

            # Generate random 16-byte salt and nonce
            salt = os.urandom(16)
            nonce = os.urandom(16)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
            )
            key = kdf.derive(self.password.encode())

            cipher = Cipher(algorithms.AES(key), CIPHER_MODE(nonce))
            encryptor = cipher.encryptor()

            total_size = os.path.getsize(src_path)
            base_progress = 40 if is_directory else 0
            range_size = 60 if is_directory else 100

            with open(src_path, 'rb') as fin, open(self.output_path, 'wb') as fout:
                fout.write(bytes([ext_length]))
                fout.write(ext_bytes.ljust(256, b'\x00'))
                fout.write(bytes([1 if is_directory else 0]))
                fout.write(salt)  # 16 bytes
                fout.write(nonce)  # 16 bytes

                processed = 0
                last_progress = -1

                while not self._cancel_requested:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    encrypted = encryptor.update(chunk)
                    fout.write(encrypted)
                    processed += len(chunk)

                    current_progress = base_progress + int((processed / total_size) * range_size)
                    if current_progress != last_progress:
                        self.progress.emit(min(100, current_progress))
                        last_progress = current_progress

                if not self._cancel_requested:
                    fout.write(encryptor.finalize())
        except Exception as e:
            if os.path.exists(self.output_path):
                os.remove(self.output_path)
            raise

class DecryptionWorker(QObject):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    _cancel_requested = False

    def __init__(self, input_path, output_dir, password):
        super().__init__()
        self.input_path = input_path
        self.output_dir = output_dir
        self.password = password
        self.is_directory = False

    def cancel(self):
        self._cancel_requested = True

    def run(self):
        try:
            self._validate_input_file()
            self._decrypt_file()
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

    def _validate_input_file(self):
        if not os.path.exists(self.input_path):
            raise ValueError("Input file does not exist")
        if os.path.getsize(self.input_path) < HEADER_SIZE:
            raise ValueError("Invalid file format")

    def _decrypt_file(self):
        self.status.emit("Decrypting...")
        with open(self.input_path, 'rb') as fin:
            ext_length = fin.read(1)[0]
            ext_bytes = fin.read(256)[:ext_length]
            self.is_directory = bool(fin.read(1)[0])
            salt = fin.read(16)  # Read 16-byte salt from header
            nonce = fin.read(16)  # Read 16-byte nonce from header

            original_ext = ext_bytes.decode('utf-8')
            if self.is_directory:
                output_file = os.path.join(self.output_dir, "temp.zip")
            else:
                base_name = os.path.basename(self.input_path).replace('.enc', '')
                output_file = os.path.join(self.output_dir, f"{base_name}{original_ext}")

            os.makedirs(self.output_dir, exist_ok=True)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
            )
            key = kdf.derive(self.password.encode())

            cipher = Cipher(algorithms.AES(key), CIPHER_MODE(nonce))
            decryptor = cipher.decryptor()


            total_size = os.path.getsize(self.input_path) - HEADER_SIZE
            processed = 0
            last_progress = -1

            with open(output_file, 'wb') as fout:
                while not self._cancel_requested:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    decrypted = decryptor.update(chunk)
                    fout.write(decrypted)
                    processed += len(chunk)

                    current_progress = int((processed / total_size) * (50 if self.is_directory else 100))
                    if current_progress != last_progress:
                        self.progress.emit(min(100, current_progress))
                        last_progress = current_progress

                if not self._cancel_requested:
                    fout.write(decryptor.finalize())

            if self.is_directory:
                self._extract_archive(output_file)

    def _extract_archive(self, zip_path):
        self.status.emit("Extracting archive...")
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            if not zipf.testzip():
                members = zipf.namelist()
                total_files = max(len(members), 1)
                for i, member in enumerate(members):
                    if self._cancel_requested: break
                    zipf.extract(member, self.output_dir)
                    self.progress.emit(50 + int((i + 1) / total_files * 50))
            else:
                raise ValueError("Invalid or corrupted ZIP file")
        if not self._cancel_requested:
            os.remove(zip_path)

class CryptoTab(QWidget):
    def __init__(self, is_encryption=True):
        super().__init__()
        self.is_encryption = is_encryption
        self.worker = None
        self.thread = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        form = QFormLayout()
        form.setVerticalSpacing(10)

        # Input Section
        self.input_path = QLineEdit()
        self.input_path.setToolTip("Select the file or directory to encrypt/decrypt.")
        self.btn_browse_input = QPushButton("📁")
        self.btn_browse_input.setToolTip("Browse for file or directory.")
        self.btn_browse_input.clicked.connect(self.browse_input)
        form.addRow("Input:", self.create_row(self.input_path, self.btn_browse_input))

        # Output Section
        self.output_path = QLineEdit()
        self.btn_browse_output = QPushButton("📁")
        self.btn_browse_output.setToolTip("Browse for output file or directory.")
        self.btn_browse_output.clicked.connect(self.browse_output)
        if self.is_encryption:
            self.output_path.setToolTip("Specify where to save the encrypted file.")
            form.addRow("Output File:", self.create_row(self.output_path, self.btn_browse_output))
        else:
            self.output_path.setToolTip("Specify directory to save decrypted files.")
            form.addRow("Output Directory:", self.create_row(self.output_path, self.btn_browse_output))

        # Password
        self.password = QLineEdit()
        self.password.setPlaceholderText("Enter password")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setToolTip("Enter a strong password for encryption/decryption.")
        form.addRow("Password:", self.password)

        if self.is_encryption:
            self.password_strength = QLabel()
            self.password.textChanged.connect(self.update_password_strength)
            form.addRow("Password Strength:", self.password_strength)

        # Encryption Mode
        if self.is_encryption:
            self.mode_group = QButtonGroup(self)
            self.file_mode = QRadioButton("File")
            self.dir_mode = QRadioButton("Directory")
            self.file_mode.setChecked(True)
            mode_layout = QHBoxLayout()
            mode_layout.addWidget(self.file_mode)
            mode_layout.addWidget(self.dir_mode)
            form.addRow("Mode:", mode_layout)
            self.mode_info = QLabel("For directories, a zip archive will be created and encrypted.")
            layout.addWidget(self.mode_info)

        # Status and Progress
        self.status_label = QLabel()
        self.progress = QProgressBar()
        self.progress.setFormat("%p%")
        self.progress.setTextVisible(True)

        # Action Button
        self.btn_action = QPushButton("🔒 Encrypt" if self.is_encryption else "🔓 Decrypt")
        self.btn_action.setToolTip("Start encryption/decryption.")
        self.btn_action.clicked.connect(self.toggle_operation)

        layout.addLayout(form)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress)
        layout.addWidget(self.btn_action)
        self.setLayout(layout)

    def create_row(self, widget, button):
        row = QHBoxLayout()
        row.addWidget(widget)
        row.addWidget(button)
        return row

    def browse_input(self):
        settings = QSettings("MyCompany", "SecureCrypt")
        last_dir = settings.value("last_directory", os.path.expanduser("~"))
        if self.is_encryption and self.dir_mode.isChecked():
            path = QFileDialog.getExistingDirectory(self, "Select Directory", last_dir)
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Select File", last_dir)
        if path:
            self.input_path.setText(path)
            settings.setValue("last_directory", os.path.dirname(path))
            self.auto_suggest_output()

    def browse_output(self):
        settings = QSettings("MyCompany", "SecureCrypt")
        last_dir = settings.value("last_directory", os.path.expanduser("~"))
        if self.is_encryption:
            path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", last_dir)
        else:
            path = QFileDialog.getExistingDirectory(self, "Select Output Directory", last_dir)
        if path:
            self.output_path.setText(path)
            settings.setValue("last_directory", path)

    def auto_suggest_output(self):
        base = self.input_path.text()
        if not base: return
        if self.is_encryption:
            base, ext = os.path.splitext(base)
            self.output_path.setText(f"{base}{ext}.enc")
        else:
            self.output_path.setText(os.path.dirname(base))

    def update_password_strength(self):
        password = self.password.text()
        if len(password) < 8:
            self.password_strength.setText("Weak")
            self.password_strength.setStyleSheet("color: red;")
        elif len(password) < 12:
            self.password_strength.setText("Medium")
            self.password_strength.setStyleSheet("color: orange;")
        else:
            self.password_strength.setText("Strong")
            self.password_strength.setStyleSheet("color: green;")

    def toggle_operation(self):
        if self.worker:
            self.cancel_operation()
        else:
            self.start_operation()

    def start_operation(self):
        if not self.validate():
            return

        if self.is_encryption:
            self.worker = EncryptionWorker(
                self.input_path.text(),
                self.output_path.text(),
                self.password.text(),
                self.dir_mode.isChecked()
            )
        else:
            self.worker = DecryptionWorker(
                self.input_path.text(),
                self.output_path.text(),
                self.password.text()
            )

        self.thread = QThread()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.handle_success)
        self.worker.error.connect(self.handle_error)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.status.connect(self.status_label.setText)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.error.connect(self.worker.deleteLater)

        self.thread.start()
        self.btn_action.setText("⏹ Cancel")
        self.toggle_ui(False)

    def cancel_operation(self):
        if self.worker:
            self.worker.cancel()
            self.btn_action.setEnabled(False)
            self.btn_action.setText("Cancelling...")
            self.thread.quit()
            self.thread.wait(500)
            self.cleanup()

    def validate(self):
        errors = []
        if not self.input_path.text():
            errors.append("Input path is required")
        elif not os.path.exists(self.input_path.text()):
            errors.append("Input path does not exist")
        if not self.output_path.text():
            errors.append("Output path is required")
        if not self.password.text():
            errors.append("Password is required")
        if errors:
            QMessageBox.warning(self, "Validation Error", "\n".join(errors))
            return False
        return True

    def toggle_ui(self, enabled):
        self.btn_action.setEnabled(True)
        self.input_path.setEnabled(enabled)
        self.output_path.setEnabled(enabled)
        self.password.setEnabled(enabled)
        if self.is_encryption:
            self.file_mode.setEnabled(enabled)
            self.dir_mode.setEnabled(enabled)

    def handle_success(self):
        QMessageBox.information(self, "Success", "Operation completed successfully!")
        self.status_label.setText("Operation completed successfully.")
        self.cleanup()

    def handle_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.status_label.setText(f"Error: {message}")
        self.cleanup()

    def cleanup(self):
        if self.thread and self.thread.isRunning():
            self.thread.quit()
            self.thread.wait(1000)
        self.worker = None
        self.thread = None
        self.toggle_ui(True)
        self.btn_action.setText("🔒 Encrypt" if self.is_encryption else "🔓 Decrypt")
        self.progress.setValue(0)

class CryptoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        icon_file = resource_path('assets/logo.png')
        self.setWindowIcon(QIcon(icon_file))
        self.setWindowTitle("SecureCrypt")
        self.setMinimumSize(600, 400)

    def init_ui(self):
        tabs = QTabWidget()
        tabs.addTab(CryptoTab(is_encryption=True), "Encrypt")
        tabs.addTab(CryptoTab(is_encryption=False), "Decrypt")
        self.setCentralWidget(tabs)

if __name__ == '__main__':
    app = QApplication([])
    window = CryptoApp()
    window.show()
    app.exec()