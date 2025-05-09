# SecureCrypt 🔐

**SecureCrypt** is a polished desktop application built with **PyQt6** and **Python**, offering robust, password-based encryption and decryption for files and directories. With AES-256-CTR, PBKDF2 key derivation, and an intuitive GUI, protecting your data has never been easier—or looked so good.

---

## ✨ Key Features

* **File & Directory Encryption**: Encrypt individual files or entire folders (directories auto-zipped).
* **Seamless Decryption**: Restore original files or unpack encrypted archives with a single click.
* **AES-256-CTR Security**: Industry-standard encryption with random salt & nonce per operation.
* **PBKDF2 with 150 000 Iterations**: Strong key stretching using SHA-256.
* **Real-time Progress & Status**: Dynamic progress bar and status messages keep you informed.
* **Password Strength Meter**: Visual feedback (Weak/Medium/Strong) encourages secure passwords.
* **Persistent Settings**: Remembers last-used directory via QSettings.

---

## 🚀 Installation

1. **Clone** this repo:

   ```bash
   git clone https://github.com/Amir-Hossein-shamsi/securecrypt.git
   cd securecrypt
   ```

2. **(Optional)** Create a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate    # Linux/macOS
   venv\\Scripts\\activate   # Windows
   ```

3. **Install** dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

## 🎬 Usage

```bash
python securecrypt.py
```

### Encrypt Tab 🔒

1. Select file or folder.
2. (Optional) Adjust output filename (`<input>.enc` by default).
3. Enter password — watch the strength meter.
4. Choose **File** or **Directory** mode.
5. Click **Encrypt**.

### Decrypt Tab 🔓

1. Select a `.enc` file.
2. Choose output directory.
3. Enter password.
4. Click **Decrypt**.

---

## 📦 Packaging

Bundle as a standalone executable with PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed securecrypt.py
```

Ensure `assets/logo.png` is included or tweak `resource_path` accordingly.

---

## ⚙️ Configuration

* **CHUNK\_SIZE** & **PBKDF2\_ITERATIONS**: Tweak in source constants.
* **Settings** stored under `MyCompany/SecureCrypt` via QSettings.

---

## 🛠 Troubleshooting

| Issue                | Solution                                    |
| -------------------- | ------------------------------------------- |
| Invalid format error | Confirm selecting a SecureCrypt `.enc` file |
| Permission denied    | Check file/folder read-write permissions    |

---

## 🤝 Contributing

Found a bug or have a feature idea? Open an issue or submit a PR. All contributions welcome!

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for full text.

---

<p align="center">Made with ❤️ and 🔒 by **Your Name**</p>
