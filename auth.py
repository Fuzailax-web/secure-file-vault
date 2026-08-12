import bcrypt
from getpass import getpass


PASSWORD_FILE = "password.hash"


def setup_password():
    password = getpass("Create a master password: ").encode()

    hashed_password = bcrypt.hashpw(
        password,
        bcrypt.gensalt()
    )

    with open(PASSWORD_FILE, "wb") as file:
        file.write(hashed_password)

    print("\n✅ Master password created successfully!")

    return password.decode()


def login():
    try:
        with open(PASSWORD_FILE, "rb") as file:
            stored_hash = file.read()

    except FileNotFoundError:
        return setup_password()

    password = getpass("Enter master password: ").encode()

    if bcrypt.checkpw(password, stored_hash):
        print("\n✅ Login Successful!")
        return password.decode()

    print("\n❌ Incorrect password!")
    return None