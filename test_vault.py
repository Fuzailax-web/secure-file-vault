import vault
import crypto


def test_initialize_vault(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(vault, "VAULT_DIR", str(vault_dir))

    vault.initialize_vault()

    assert vault_dir.exists()
    assert vault_dir.is_dir()


def test_encrypt_to_vault(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(vault, "VAULT_DIR", str(vault_dir))

    source_file = tmp_path / "secret.txt"
    source_file.write_text("Secure File Vault test data")

    key = crypto.derive_key(
        "TestPassword123",
        b"1234567890123456"
    )

    result = vault.encrypt_to_vault(str(source_file), key)

    assert result == str(vault_dir / "secret.txt.encrypted")
    assert (vault_dir / "secret.txt.encrypted").exists()
    assert (vault_dir / "secret.txt.encrypted.sha256").exists()


def test_list_vault_files(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(vault, "VAULT_DIR", str(vault_dir))

    vault.initialize_vault()

    (vault_dir / "first.txt.encrypted").write_bytes(b"data")
    (vault_dir / "second.txt.encrypted").write_bytes(b"data")
    (vault_dir / "notes.txt").write_text("not encrypted")

    files = vault.list_vault_files()

    assert len(files) == 2
    assert "first.txt.encrypted" in files
    assert "second.txt.encrypted" in files
    assert "notes.txt" not in files


def test_verify_file_integrity(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(vault, "VAULT_DIR", str(vault_dir))

    vault.initialize_vault()

    encrypted_file = vault_dir / "secret.txt.encrypted"
    encrypted_file.write_bytes(b"encrypted test data")

    file_hash = vault.calculate_hash(str(encrypted_file))
    vault.save_hash(str(encrypted_file), file_hash)

    assert vault.verify_file_integrity(str(encrypted_file)) is True


def test_delete_from_vault(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(vault, "VAULT_DIR", str(vault_dir))

    vault.initialize_vault()

    encrypted_file = vault_dir / "secret.txt.encrypted"
    encrypted_file.write_bytes(b"encrypted test data")

    hash_file = vault_dir / "secret.txt.encrypted.sha256"
    hash_file.write_text("test hash")

    monkeypatch.setattr("builtins.input", lambda _: "y")

    result = vault.delete_from_vault("secret.txt.encrypted")

    assert result is True
    assert not encrypted_file.exists()
    assert not hash_file.exists()

def test_decrypt_from_vault_success(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(vault, "VAULT_DIR", str(vault_dir))

    original_file = tmp_path / "secret.txt"
    original_content = b"Secure File Vault decryption test"

    original_file.write_bytes(original_content)

    key = crypto.derive_key(
        "TestPassword123",
        b"1234567890123456"
    )

    encrypted_path = vault.encrypt_to_vault(
        str(original_file),
        key
    )

    result = vault.decrypt_from_vault(
        "secret.txt.encrypted",
        key
    )

    output_file = tmp_path / "decrypted_secret.txt"

def test_decrypt_from_vault_detects_tampering(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(vault, "VAULT_DIR", str(vault_dir))
    monkeypatch.chdir(tmp_path)

    original_file = tmp_path / "secret.txt"
    original_file.write_bytes(b"Secure File Vault tamper test")

    key = crypto.derive_key(
        "TestPassword123",
        b"1234567890123456"
    )

    vault.encrypt_to_vault(str(original_file), key)

    # Simulate an attacker modifying the encrypted file
    encrypted_file = vault_dir / "secret.txt.encrypted"
    with open(encrypted_file, "ab") as f:
        f.write(b"tampered")

    try:
        result = vault.decrypt_from_vault("secret.txt.encrypted", key)
    except Exception:
        result = None

    output_file = tmp_path / "decrypted_secret.txt"

    assert not result
    assert not output_file.exists()

def test_decrypt_from_vault_wrong_key(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(vault, "VAULT_DIR", str(vault_dir))
    monkeypatch.chdir(tmp_path)

    original_file = tmp_path / "secret.txt"
    original_file.write_bytes(b"Secure File Vault wrong key test")

    salt = b"1234567890123456"

    correct_key = crypto.derive_key("TestPassword123", salt)
    wrong_key = crypto.derive_key("WrongPassword456", salt)

    vault.encrypt_to_vault(str(original_file), correct_key)

    try:
        result = vault.decrypt_from_vault("secret.txt.encrypted", wrong_key)
    except Exception:
        result = None

    output_file = tmp_path / "decrypted_secret.txt"

    assert not result
    assert not output_file.exists()

def test_decrypt_from_vault_missing_file(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(vault, "VAULT_DIR", str(vault_dir))
    monkeypatch.chdir(tmp_path)

    vault.initialize_vault()

    key = crypto.derive_key(
        "TestPassword123",
        b"1234567890123456"
    )

    try:
        result = vault.decrypt_from_vault("does_not_exist.txt.encrypted", key)
    except Exception:
        result = None

    assert not result
    assert not (tmp_path / "does_not_exist.txt").exists()


def test_delete_from_vault_cancelled(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(vault, "VAULT_DIR", str(vault_dir))

    vault.initialize_vault()

    encrypted_file = vault_dir / "secret.txt.encrypted"
    encrypted_file.write_bytes(b"encrypted test data")

    hash_file = vault_dir / "secret.txt.encrypted.sha256"
    hash_file.write_text("test hash")

    monkeypatch.setattr("builtins.input", lambda _: "n")

    result = vault.delete_from_vault("secret.txt.encrypted")

    assert not result
    assert encrypted_file.exists()
    assert hash_file.exists()