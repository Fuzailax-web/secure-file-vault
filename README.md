# 🔐 Secure File Vault

A Python command-line vault that protects sensitive files with password-based authentication, authenticated encryption, and integrity verification.

The project demonstrates core cybersecurity concepts: password hashing, cryptographic key derivation, authenticated encryption, hashing, tamper detection, input validation, and security logging.

## ✨ Features

- **Master password authentication:** the password is stored only as a bcrypt hash; the first run creates it.
- **Key derivation:** PBKDF2-HMAC-SHA256 (600,000 iterations) with a random 16-byte salt turns the password into an encryption key.
- **File encryption and decryption:** Fernet authenticated symmetric encryption.
- **Integrity verification:** a SHA-256 hash of every encrypted file is saved and checked before decryption.
- **Tamper detection:** a modified file is rejected and never decrypted.
- **Safe file handling:** delete confirmation, no silent overwrites, and path-traversal protection.
- **Security logging:** logins, encryption, decryption, integrity checks, and deletions are written to `vault.log` and can be viewed from the menu.
- **Automated tests:** 23 pytest tests.

## 🛠️ Technologies

Python · cryptography (Fernet, PBKDF2HMAC) · bcrypt · hashlib (SHA-256) · logging · pytest

## 📁 Project Structure

```text
secure-file-vault/
├── main.py             # menu and program entry point
├── auth.py             # master password setup and login (bcrypt)
├── crypto.py           # salt, key derivation, Fernet helpers
├── integrity.py        # SHA-256 hashing and verification
├── vault.py            # encrypt, list, verify, decrypt, delete
├── logger.py           # security logging
├── test_auth.py
├── test_crypto.py
├── test_integrity.py
├── test_vault.py
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

```bash
python main.py
```

On the first run you create a master password. Then choose from the menu:

| Option | Action |
|---|---|
| 1 | Encrypt a file into the vault |
| 2 | List vault files |
| 3 | Decrypt a file (integrity is checked first) |
| 4 | Delete a vault file (with confirmation) |
| 5 | View security logs |
| 6 | Exit |

Encrypted files are stored in `vault/` as `name.encrypted` with a matching `name.encrypted.sha256` hash. Decrypted files are written to the current folder as `decrypted_name`.

## 🔒 Security Design

- **Authentication:** bcrypt hashes the master password with a per-password salt. The plain password is never stored.
- **Key derivation:** the encryption key is derived from the password and `vault.salt` with PBKDF2-HMAC-SHA256. The key itself is never written to disk.
- **Encryption:** Fernet provides authenticated encryption, so a wrong key or modified data fails to decrypt.
- **Integrity:** the SHA-256 hash of the encrypted file is verified before any decryption attempt. A mismatch stops the operation.
- **Path-traversal protection:** filenames are reduced to their base name, so a name like `../file.encrypted` cannot reach outside the vault folder.
- **Logging:** security-relevant events are logged with timestamps.

### Limitations

- **A forgotten master password cannot be recovered.** Files cannot be decrypted without it.
- Keep `vault.salt`; without it the key cannot be re-derived.
- The hash file sits next to the encrypted file, so on its own it cannot prove authenticity if an attacker can change both. Fernet's built-in authentication still rejects modified data.
- Original files are not securely wiped after encryption.

## 🧪 Testing

```bash
python -m pytest -v
```

| Test file | Covers |
|---|---|
| test_auth.py | master password creation and login |
| test_crypto.py | salt, key derivation, encryption |
| test_integrity.py | SHA-256 hashing and tamper detection |
| test_vault.py | vault operations: encrypt, list, verify, decrypt, delete, tampering, wrong key, missing file, cancelled delete, path traversal |

**Result: 23 tests passing** (12 in `test_vault.py`).

## 🔮 Future Improvements

- Recovery key for a forgotten master password
- Standalone "verify integrity" menu option
- Password-strength validation
- Secure wiping of original files after encryption
- Folder encryption and a graphical interface
- Continuous integration for the test suite

## ⚠️ Disclaimer

This is an educational project and has not been independently audited. Do not rely on it as the sole protection for highly sensitive data.

## 👨‍💻 Author

**Fuzail Shaikh**
