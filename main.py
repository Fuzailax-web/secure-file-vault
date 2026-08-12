from auth import login
from crypto import generate_salt, derive_key, load_salt
from vault import (
    initialize_vault,
    encrypt_to_vault,
    list_vault_files,
    decrypt_from_vault,
    delete_from_vault
)


# Login
password = login()

if password is None:
    print("\n🔒 Access denied!")
    exit()


# Load or generate salt
try:
    salt = load_salt()
except FileNotFoundError:
    salt = generate_salt()


# Derive encryption key
key = derive_key(password, salt)

# Initialize vault
initialize_vault()


# Main menu
while True:

    print("\n========== Secure File Vault ==========")
    print("1. Encrypt File")
    print("2. List Vault Files")
    print("3. Decrypt File")
    print("4. Delete Vault File")
    print("5. Exit")

    choice = input("\nEnter your choice: ").strip()

    # Encrypt
    if choice == "1":

        filename = input(
            "Enter file to encrypt: "
        ).strip()

        encrypt_to_vault(filename, key)

    # List
    elif choice == "2":

        list_vault_files()

    # Decrypt
    elif choice == "3":

        files = list_vault_files()

        if files:

            try:
                number = int(
                    input("\nEnter file number to decrypt: ")
                )

                if 1 <= number <= len(files):

                    decrypt_from_vault(
                        files[number - 1],
                        key
                    )

                else:
                    print("\n❌ Invalid file number!")

            except ValueError:
                print("\n❌ Please enter a number!")

    # Delete
    elif choice == "4":

        files = list_vault_files()

        if files:

            try:
                number = int(
                    input("\nEnter file number to delete: ")
                )

                if 1 <= number <= len(files):

                    delete_from_vault(
                        files[number - 1]
                    )

                else:
                    print("\n❌ Invalid file number!")

            except ValueError:
                print("\n❌ Please enter a number!")

    # Exit
    elif choice == "5":

        print("\n🔒 Vault locked.")
        print("Thank you for using Secure File Vault!")
        break

    else:

        print("\n❌ Invalid choice!")
