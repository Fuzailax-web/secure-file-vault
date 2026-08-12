import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SALT_FILE = "vault.salt"


def generate_salt():
    salt = os.urandom(16)

    with open(SALT_FILE, "wb") as file:
        file.write(salt)

    return salt


def load_salt():
    with open(SALT_FILE, "rb") as file:
        return file.read()


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000
    )

    key = base64.urlsafe_b64encode(
        kdf.derive(password.encode())
    )

    return key


def encrypt_file(filename, key):
    fernet = Fernet(key)

    with open(filename, "rb") as file:
        data = file.read()

    encrypted_data = fernet.encrypt(data)

    encrypted_filename = filename + ".encrypted"

    with open(encrypted_filename, "wb") as file:
        file.write(encrypted_data)

    return encrypted_filename


def decrypt_file(filename, key):
    fernet = Fernet(key)

    with open(filename, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    if filename.endswith(".encrypted"):
        decrypted_filename = filename[:-10]
    else:
        decrypted_filename = filename + ".decrypted"

    with open(decrypted_filename, "wb") as file:
        file.write(decrypted_data)

    return decrypted_filename