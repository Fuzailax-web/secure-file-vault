from auth import login
from crypto import generate_salt, derive_key, load_salt

from vault import (
    initialize_vault,
    encrypt_to_vault,
    list_vault_files,
    decrypt_from_vault,
    delete_from_vault
)

from logger import logger


def show_banner():
    print("\n")
    print("╔════════════════════════════════════════╗")
    print("║        🔐 SECURE FILE VAULT            ║")
    print("╠════════════════════════════════════════╣")
    print("║     Secure Storage & Encryption        ║")
    print("╚════════════════════════════════════════╝")


def show_menu():
    print("\n╔════════════════════════════════════════╗")
    print("║              MAIN MENU                 ║")
    print("╠════════════════════════════════════════╣")
    print("║  1. 🔒 Encrypt File                   ║")
    print("║  2. 📁 List Vault Files               ║")
    print("║  3. 🔓 Decrypt File                   ║")
    print("║  4. 🗑️  Delete Vault File             ║")
    print("║  5. 📋 View Security Logs             ║")
    print("║  6. 🚪 Exit                           ║")
    print("╚════════════════════════════════════════╝")


def view_logs():

    print("\n========== Security Logs ==========")

    try:
        with open("vault.log", "r") as file:
            logs = file.read()

        if logs.strip() == "":
            print("\n📋 No logs available.")

        else:
            print(logs)

    except FileNotFoundError:
        print("\n📋 No log file found.")


def encrypt_file(key):

    filename = input(
        "\n📄 Enter file to encrypt: "
    ).strip()

    if filename == "":
        print("\n❌ File name cannot be empty!")
        return

    encrypt_to_vault(filename, key)


def decrypt_file(key):

    files = list_vault_files()

    if not files:
        return

    try:
        number = int(
            input("\n🔢 Enter file number to decrypt: ")
        )

    except ValueError:
        print("\n❌ Please enter a valid number!")
        return

    if number < 1 or number > len(files):
        print("\n❌ Invalid file number!")
        return

    decrypt_from_vault(
        files[number - 1],
        key
    )


def delete_file():

    files = list_vault_files()

    if not files:
        return

    try:
        number = int(
            input("\n🔢 Enter file number to delete: ")
        )

    except ValueError:
        print("\n❌ Please enter a valid number!")
        return

    if number < 1 or number > len(files):
        print("\n❌ Invalid file number!")
        return

    delete_from_vault(
        files[number - 1]
    )


def main():

    show_banner()

    password = login()

    if password is None:

        logger.warning("Login failed")

        print("\n🔒 Access denied!")
        return

    logger.info("Login successful")

    try:
        salt = load_salt()

    except FileNotFoundError:
        salt = generate_salt()

    key = derive_key(
        password,
        salt
    )

    initialize_vault()

    while True:

        show_menu()

        choice = input(
            "\n👉 Enter your choice: "
        ).strip()

        if choice == "1":

            encrypt_file(key)

        elif choice == "2":

            list_vault_files()

        elif choice == "3":

            decrypt_file(key)

        elif choice == "4":

            delete_file()

        elif choice == "5":

            view_logs()

        elif choice == "6":

            print("\n🔒 Vault locked.")
            print(
                "Thank you for using Secure File Vault!"
            )

            logger.info(
                "Vault session ended"
            )

            break

        else:

            print(
                "\n❌ Invalid choice!"
            )
            print(
                "Please select a number from 1 to 6."
            )


if __name__ == "__main__":
    main()