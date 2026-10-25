import crypto


def test_generate_and_load_salt(tmp_path, monkeypatch):
    salt_file = tmp_path / "vault.salt"

    monkeypatch.setattr(crypto, "SALT_FILE", str(salt_file))

    generated_salt = crypto.generate_salt()
    loaded_salt = crypto.load_salt()

    assert len(generated_salt) == 16
    assert loaded_salt == generated_salt


def test_derive_key():
    password = "TestPassword123"
    salt = b"1234567890123456"

    key = crypto.derive_key(password, salt)

    assert len(key) == 44


def test_same_password_and_salt_produce_same_key():
    password = "TestPassword123"
    salt = b"1234567890123456"

    key1 = crypto.derive_key(password, salt)
    key2 = crypto.derive_key(password, salt)

    assert key1 == key2


def test_encrypt_and_decrypt(tmp_path):
    original_file = tmp_path / "secret.txt"
    original_content = b"Secure File Vault Test Data"

    original_file.write_bytes(original_content)

    key = crypto.derive_key(
        "TestPassword123",
        b"1234567890123456"
    )

    encrypted_file = crypto.encrypt_file(
        str(original_file),
        key
    )

    decrypted_file = crypto.decrypt_file(
        encrypted_file,
        key
    )

    assert encrypted_file.endswith(".encrypted")
    assert decrypted_file.endswith("secret.txt")
    assert decrypted_file != encrypted_file

    assert open(decrypted_file, "rb").read() == original_content