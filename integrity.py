import hashlib
from pathlib import Path


def calculate_hash(filename):
    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def save_hash(filename, file_hash):
    hash_filename = Path(str(filename) + ".sha256")

    with open(hash_filename, "w") as file:
        file.write(file_hash)

    return hash_filename


def load_hash(filename):
    hash_filename = Path(str(filename) + ".sha256")

    with open(hash_filename, "r") as file:
        return file.read().strip()


def verify_hash(filename, expected_hash):
    actual_hash = calculate_hash(filename)

    return actual_hash == expected_hash