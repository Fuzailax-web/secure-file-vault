# 🔐 Secure File Vault

[![Tests](https://github.com/Fuzailax-web/secure-file-vault/actions/workflows/tests.yml/badge.svg)](https://github.com/Fuzailax-web/secure-file-vault/actions/workflows/tests.yml)

A Python file vault with a web interface and a command-line interface. It protects sensitive files with password-based authentication, authenticated encryption, and integrity verification. Everything runs locally on your own computer.

The project demonstrates core cybersecurity concepts: password hashing, key derivation, authenticated encryption, tamper detection, session management, login rate limiting, input validation, and security logging.

## ✨ Features

- **Master password authentication:** the password is stored only as a bcrypt hash.
- **Key derivation:** PBKDF2-HMAC-SHA256 (600,000 iterations) with a random 16-byte salt turns the password into an encryption key.
- **File encryption:** Fernet authenticated symmetric encryption.
- **Integrity verification:** a SHA-256 hash of each encrypted file is saved and checked before decryption.
- **Tamper detection:** a modified file is rejected and never decrypted.
- **Web interface:** log in, upload and encrypt, verify, download and decrypt, delete, and view the security log. Works on phones, with light and dark themes.
- **Command-line interface:** the same vault from the terminal.
- **Security logging:** logins, encryption, decryption, integrity checks and deletions are written to `vault.log`.
- **Automated tests:** 82 pytest tests.

## 🛡️ Web Security Measures

- Sessions use random 256-bit tokens in `HttpOnly`, `SameSite=Strict` cookies. The encryption key stays in server memory and is never sent to the browser.
- Sessions expire after 10 minutes of inactivity.
- After 5 failed logins, login is locked for 60 seconds.
- Cross-origin state-changing requests are rejected.
- A Content-Security-Policy blocks inline and third-party scripts. File names are always rendered as plain text, never as HTML.
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Cache-Control: no-store`.
- Uploads are limited to 10 MB and file names are reduced to a safe base name, which blocks path traversal.
- Files are encrypted in memory; no unencrypted copy is written to disk by the web app.

## 🛠️ Technologies

Python · FastAPI · Uvicorn · cryptography (Fernet, PBKDF2HMAC) · bcrypt · SHA-256 · HTML, CSS and JavaScript · pytest

## 📁 Project Structure

```text
secure-file-vault/
├── app.py              # FastAPI web server and API
├── core.py             # vault logic used by the web app
├── static/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── main.py             # command-line menu
├── auth.py             # command-line login (bcrypt)
├── vault.py            # command-line vault operations
├── crypto.py           # salt and key derivation
├── integrity.py        # SHA-256 hashing and verification
├── logger.py           # security logging
├── test_auth.py
├── test_crypto.py
├── test_integrity.py
├── test_vault.py
├── test_core.py
├── test_api.py
├── requirements.txt
└── README.md
```

Created at runtime (never commit these): `password.hash`, `vault.salt`, `vault/`, `vault.log`.

## ⚙️ Installation

```bash
git clone <YOUR_REPOSITORY_URL>
cd secure-file-vault
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
python -m pip install -r requirements.txt
```

## 🚀 Usage

### Web interface

```bash
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. On the first run you create a master password. Then add files, verify them, download them, or delete them. Stop the server with Ctrl + C.

Interactive API documentation is available at http://127.0.0.1:8000/docs.

### Command line

```bash
python main.py
```

The web interface and the command line share the same vault, password and salt.

## 🔒 Security Design

- **Authentication:** bcrypt hashes the master password with a per-password salt. The plain password is never stored.
- **Key derivation:** the encryption key comes from the password and `vault.salt` using PBKDF2-HMAC-SHA256. The key is never written to disk.
- **Encryption:** Fernet provides authenticated encryption, so a wrong key or modified data fails to decrypt.
- **Integrity:** the SHA-256 hash of the encrypted file is verified before any decryption attempt. A mismatch stops the operation.

### Limitations

- **A forgotten master password cannot be recovered.** Files cannot be decrypted without it.
- Keep `vault.salt`; without it the key cannot be re-derived.
- The hash file sits next to the encrypted file, so on its own it cannot prove authenticity if an attacker can change both. Fernet's built-in authentication still rejects modified data.
- This is a single-user, local application served over plain HTTP on `127.0.0.1`. **Do not expose it to the internet** without HTTPS and a reverse proxy.
- Sessions and the login lockout live in server memory, so restarting the server logs everyone out.

## 🧪 Testing

```bash
python -m pytest -v
```

| Test file | Covers |
|---|---|
| test_auth.py, test_crypto.py, test_integrity.py | master password, key derivation, encryption, hashing |
| test_vault.py | command-line vault: encrypt, decrypt, tampering, wrong key, path traversal |
| test_core.py | web vault logic: roundtrip, tampering, wrong key, filename cleaning, size limit |
| test_api.py | sessions, lockout, access control, uploads and downloads, cross-origin blocking, security headers |

**Result: 82 tests passing.**

## 🔮 Future Improvements

- Recovery key for a forgotten master password
- HTTPS support and deployment guide
- Password-strength meter
- Secure wiping of original files
- Folder encryption
- Continuous integration for the test suite

## ⚠️ Disclaimer

This is an educational project and has not been independently audited. Do not rely on it as the sole protection for highly sensitive data.

## 👨‍💻 Author

**Fuzail Shaikh**
