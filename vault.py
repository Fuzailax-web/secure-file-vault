import os

from cryptography.fernet import Fernet

from integrity import (
    calculate_hash,
    save_hash,
    load_hash,
    verify_hash
)

from logger import logger


VAULT_DIR = "vault"


def initialize_vault():
    if not os.path.exists(VAULT_DIR):
        os.makedirs(VAULT_DIR)


def encrypt_to_vault(filename, key):

    if not os.path.isfile(filename):
        print("\n❌ File not found!")
        return None

    initialize_vault()

    with open(filename, "rb") as file:
        data = file.read()

    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    original_name = os.path.basename(filename)
    encrypted_filename = original_name + ".encrypted"

    vault_path = os.path.join(
        VAULT_DIR,
        encrypted_filename
    )

    with open(vault_path, "wb") as file:
        file.write(encrypted_data)

    # Create SHA-256 integrity hash
    file_hash = calculate_hash(vault_path)

    hash_path = save_hash(
        vault_path,
        file_hash
    )

    print("\n✅ File encrypted and stored in vault!")
    print(f"📁 Vault file: {vault_path}")
    print(f"🔐 Integrity hash: {hash_path}")

    logger.info(
        f"File encrypted: {filename}"
    )

    return vault_path


def list_vault_files():

    initialize_vault()

    files = os.listdir(VAULT_DIR)

    encrypted_files = [
        file
        for file in files
        if file.endswith(".encrypted")
    ]

    if not encrypted_files:
        print("\n📁 Vault is empty!")
        return []

    print("\n========== Vault Files ==========")

    for index, file in enumerate(
        encrypted_files,
        start=1
    ):
        print(f"{index}. {file}")

    return encrypted_files


def verify_file_integrity(vault_path):

    try:
        expected_hash = load_hash(vault_path)

    except FileNotFoundError:

        print("\n⚠️ Integrity hash not found!")

        logger.warning(
            f"Integrity hash missing: {vault_path}"
        )

        return False

    if verify_hash(
        vault_path,
        expected_hash
    ):

        print("\n✅ File integrity verified!")

        logger.info(
            f"Integrity verified: {vault_path}"
        )

        return True

    print("\n❌ Integrity check failed!")
    print(
        "⚠️ The encrypted file may have "
        "been modified or corrupted."
    )

    logger.warning(
        f"Integrity check failed: {vault_path}"
    )

    return False


def decrypt_from_vault(filename, key):

    vault_path = os.path.join(
        VAULT_DIR,
        filename
    )

    if not os.path.isfile(vault_path):

        print("\n❌ Vault file not found!")

        logger.warning(
            f"Vault file not found: {filename}"
        )

        return None

    if not filename.endswith(".encrypted"):

        print("\n❌ Invalid encrypted file!")

        logger.warning(
            f"Invalid encrypted file: {filename}"
        )

        return None

    # Verify integrity before decrypting
    if not verify_file_integrity(vault_path):
        return None

    with open(vault_path, "rb") as file:
        encrypted_data = file.read()

    try:

        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(
            encrypted_data
        )

    except Exception:

        print("\n❌ Decryption failed!")
        print(
            "The password/key may be incorrect "
            "or the file may be corrupted."
        )

        logger.error(
            f"Decryption failed: {filename}"
        )

        return None

    original_filename = filename[:-10]

    output_filename = (
        "decrypted_" + original_filename
    )

    if os.path.exists(output_filename):

        print("\n❌ Decrypted file already exists!")
        print(
            f"Existing file: {output_filename}"
        )

        logger.warning(
            f"Decryption skipped because file "
            f"already exists: {output_filename}"
        )

        return None

    with open(
        output_filename,
        "wb"
    ) as file:

        file.write(decrypted_data)

    print("\n✅ File decrypted successfully!")
    print(
        f"📄 Output file: {output_filename}"
    )

    logger.info(
        f"File decrypted: {filename}"
    )

    return output_filename


def delete_from_vault(filename):

    vault_path = os.path.join(
        VAULT_DIR,
        filename
    )

    if not os.path.isfile(vault_path):

        print("\n❌ Vault file not found!")

        logger.warning(
            f"Delete failed - file not found: {filename}"
        )

        return False

    confirm = input(
        f"\nAre you sure you want to delete "
        f"'{filename}'? (y/n): "
    ).strip().lower()

    if confirm != "y":

        print("\n❌ Delete cancelled!")

        logger.info(
            f"Delete cancelled: {filename}"
        )

        return False

    hash_path = vault_path + ".sha256"

    os.remove(vault_path)

    if os.path.exists(hash_path):
        os.remove(hash_path)

    print(
        "\n✅ Vault file deleted successfully!"
    )

    logger.info(
        f"Vault file deleted: {filename}"
    )

    return True