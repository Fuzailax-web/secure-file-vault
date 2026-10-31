"""Core vault logic for the web app.

Unlike vault.py, nothing here prints or asks for input. Functions return
values or raise clear exceptions, so any interface (web, GUI, CLI) can
decide how to show them.
"""

import os

import bcrypt
from cryptography.fernet import Fernet, InvalidToken

import crypto
import integrity
from logger import logger

PASSWORD_FILE = "password.hash"
VAULT_DIR = "vault"

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_BYTES = 72  # bcrypt limit
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


# ---------- Errors ----------

class VaultError(Exception):
    """Base class for all vault errors."""


class InvalidFilenameError(VaultError):
    pass


class FileTooLargeError(VaultError):
    pass


class VaultFileNotFoundError(VaultError):
    pass


class VaultFileExistsError(VaultError):
    pass


class TamperDetectedError(VaultError):
    pass


class WrongKeyError(VaultError):
    pass


class WeakPasswordError(VaultError):
    pass


class PasswordAlreadySetError(VaultError):
    pass


# ---------- Master password ----------

def password_is_set():
    return os.path.isfile(PASSWORD_FILE)


def set_master_password(password):
    if password_is_set():
        raise PasswordAlreadySetError("A master password already exists.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )

    if len(password.encode()) > MAX_PASSWORD_BYTES:
        raise WeakPasswordError(
            f"Password must be at most {MAX_PASSWORD_BYTES} bytes."
        )

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    with open(PASSWORD_FILE, "wb") as file:
        file.write(hashed)

    logger.info("Master password created")


def check_password(password):
    if not password_is_set():
        return False

    encoded = password.encode()

    if len(encoded) > MAX_PASSWORD_BYTES:
        logger.warning("Login failed")
        return False

    with open(PASSWORD_FILE, "rb") as file:
        stored_hash = file.read()

    if bcrypt.checkpw(encoded, stored_hash):
        logger.info("Login successful")
        return True

    logger.warning("Login failed")
    return False


def derive_vault_key(password):
    """Derive the Fernet key. Creates the salt only if it doesn't exist."""
    if os.path.exists(crypto.SALT_FILE):
        salt = crypto.load_salt()
    else:
        salt = crypto.generate_salt()

    return crypto.derive_key(password, salt)


# ---------- File names ----------

def clean_filename(filename):
    """Reduce a user-supplied name to a safe base name."""
    name = (filename or "").replace("\\", "/")
    name = os.path.basename(name).strip()

    if not name or name in (".", "..") or "\x00" in name:
        raise InvalidFilenameError("Invalid file name.")

    return name


def _vault_name(vault_name):
    name = clean_filename(vault_name)

    if not name.endswith(".encrypted"):
        raise InvalidFilenameError("Not a vault file.")

    return name


def _path(vault_name):
    return os.path.join(VAULT_DIR, vault_name)


# ---------- Vault operations ----------

def store_file(filename, data, key):
    """Encrypt bytes into the vault. Returns the vault file name."""
    name = clean_filename(filename)

    if len(data) > MAX_FILE_SIZE:
        raise FileTooLargeError("File is too large.")

    os.makedirs(VAULT_DIR, exist_ok=True)

    vault_name = name + ".encrypted"
    path = _path(vault_name)

    if os.path.exists(path):
        raise VaultFileExistsError("A vault file with this name exists.")

    encrypted = Fernet(key).encrypt(data)

    with open(path, "wb") as file:
        file.write(encrypted)

    integrity.save_hash(path, integrity.calculate_hash(path))

    logger.info(f"File encrypted: {name}")

    return vault_name


def list_files():
    os.makedirs(VAULT_DIR, exist_ok=True)

    items = []

    for name in sorted(os.listdir(VAULT_DIR)):
        if name.endswith(".encrypted"):
            stat = os.stat(_path(name))
            items.append({
                "name": name,
                "size": stat.st_size,
                "modified": stat.st_mtime,
            })

    return items


def verify_file(vault_name):
    """Return True if the file matches its saved SHA-256 hash."""
    name = _vault_name(vault_name)
    path = _path(name)

    if not os.path.isfile(path):
        raise VaultFileNotFoundError("Vault file not found.")

    try:
        expected = integrity.load_hash(path)
    except FileNotFoundError:
        logger.warning(f"Integrity hash missing: {name}")
        return False

    if integrity.verify_hash(path, expected):
        logger.info(f"Integrity verified: {name}")
        return True

    logger.warning(f"Integrity check failed: {name}")
    return False


def read_file(vault_name, key):
    """Verify and decrypt. Returns (original_name, bytes)."""
    name = _vault_name(vault_name)
    path = _path(name)

    if not os.path.isfile(path):
        raise VaultFileNotFoundError("Vault file not found.")

    if not verify_file(name):
        raise TamperDetectedError(
            "Integrity check failed. The file may have been modified."
        )

    with open(path, "rb") as file:
        encrypted = file.read()

    try:
        data = Fernet(key).decrypt(encrypted)
    except InvalidToken:
        logger.error(f"Decryption failed: {name}")
        raise WrongKeyError("Wrong key or corrupted file.")

    logger.info(f"File decrypted: {name}")

    return name[: -len(".encrypted")], data


def delete_file(vault_name):
    name = _vault_name(vault_name)
    path = _path(name)

    if not os.path.isfile(path):
        raise VaultFileNotFoundError("Vault file not found.")

    os.remove(path)

    hash_path = path + ".sha256"
    if os.path.exists(hash_path):
        os.remove(hash_path)

    logger.info(f"Vault file deleted: {name}")
