import os

from cryptography.fernet import Fernet


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

    print("\n✅ File encrypted and stored in vault!")
    print(f"📁 Vault file: {vault_path}")

    return vault_path


def list_vault_files():
    initialize_vault()

    files = os.listdir(VAULT_DIR)

    encrypted_files = [
        file for file in files
        if file.endswith(".encrypted")
    ]

    if not encrypted_files:
        print("\n📁 Vault is empty!")
        return []

    print("\n========== Vault Files ==========")

    for index, file in enumerate(encrypted_files, start=1):
        print(f"{index}. {file}")

    return encrypted_files


def decrypt_from_vault(filename, key):
    vault_path = os.path.join(VAULT_DIR, filename)

    if not os.path.isfile(vault_path):
        print("\n❌ Vault file not found!")
        return None

    if not filename.endswith(".encrypted"):
        print("\n❌ Invalid encrypted file!")
        return None

    with open(vault_path, "rb") as file:
        encrypted_data = file.read()

    try:
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        print("\n❌ Decryption failed!")
        print("The password/key may be incorrect or the file may be corrupted.")
        return None

    original_filename = filename[:-10]

    output_filename = "decrypted_" + original_filename

    if os.path.exists(output_filename):
        print("\n❌ Decrypted file already exists!")
        print(f"Existing file: {output_filename}")
        return None

    with open(output_filename, "wb") as file:
        file.write(decrypted_data)

    print("\n✅ File decrypted successfully!")
    print(f"📄 Output file: {output_filename}")

    return output_filename

def delete_from_vault(filename):
    vault_path = os.path.join(VAULT_DIR, filename)

    if not os.path.isfile(vault_path):
        print("\n❌ Vault file not found!")
        return False

    confirm = input(
        f"\nAre you sure you want to delete '{filename}'? (y/n): "
    ).strip().lower()

    if confirm != "y":
        print("\n❌ Delete cancelled!")
        return False

    os.remove(vault_path)

    print("\n✅ Vault file deleted successfully!")

    return True