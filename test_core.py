import os

import pytest

import core
import crypto


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Run every test inside its own empty temporary folder."""
    monkeypatch.chdir(tmp_path)


@pytest.fixture(scope="module")
def key():
    return crypto.derive_key("TestPassword123", b"1234567890123456")


@pytest.fixture(scope="module")
def other_key():
    return crypto.derive_key("WrongPassword456", b"1234567890123456")


# ---------- Master password ----------

def test_set_and_check_password():
    assert core.password_is_set() is False

    core.set_master_password("CorrectHorse1")

    assert core.password_is_set() is True
    assert core.check_password("CorrectHorse1") is True
    assert core.check_password("wrong-password") is False


def test_weak_password_rejected():
    with pytest.raises(core.WeakPasswordError):
        core.set_master_password("short")

    assert core.password_is_set() is False


def test_too_long_password_rejected():
    with pytest.raises(core.WeakPasswordError):
        core.set_master_password("a" * 73)


def test_cannot_set_password_twice():
    core.set_master_password("CorrectHorse1")

    with pytest.raises(core.PasswordAlreadySetError):
        core.set_master_password("AnotherPass22")


def test_check_password_without_setup():
    assert core.check_password("anything") is False


# ---------- Store and read ----------

def test_store_and_read_roundtrip(key):
    name = core.store_file("notes.txt", b"hello vault", key)

    assert name == "notes.txt.encrypted"

    original_name, data = core.read_file(name, key)

    assert original_name == "notes.txt"
    assert data == b"hello vault"


def test_list_files(key):
    assert core.list_files() == []

    core.store_file("a.txt", b"1", key)
    core.store_file("b.txt", b"2", key)

    names = [item["name"] for item in core.list_files()]

    assert names == ["a.txt.encrypted", "b.txt.encrypted"]


def test_duplicate_name_rejected(key):
    core.store_file("a.txt", b"1", key)

    with pytest.raises(core.VaultFileExistsError):
        core.store_file("a.txt", b"2", key)


def test_file_too_large_rejected(key, monkeypatch):
    monkeypatch.setattr(core, "MAX_FILE_SIZE", 10)

    with pytest.raises(core.FileTooLargeError):
        core.store_file("big.bin", b"x" * 11, key)


# ---------- Security ----------

def test_tampering_detected(key):
    name = core.store_file("secret.txt", b"top secret", key)

    with open("vault/" + name, "ab") as file:
        file.write(b"tampered")

    assert core.verify_file(name) is False

    with pytest.raises(core.TamperDetectedError):
        core.read_file(name, key)


def test_missing_hash_counts_as_failed_integrity(key):
    name = core.store_file("secret.txt", b"top secret", key)
    os.remove("vault/" + name + ".sha256")

    assert core.verify_file(name) is False

    with pytest.raises(core.TamperDetectedError):
        core.read_file(name, key)


def test_wrong_key_rejected(key, other_key):
    name = core.store_file("secret.txt", b"top secret", key)

    with pytest.raises(core.WrongKeyError):
        core.read_file(name, other_key)


def test_filename_traversal_is_cleaned(key):
    name = core.store_file("../../evil.txt", b"data", key)

    assert name == "evil.txt.encrypted"
    assert os.path.exists("vault/evil.txt.encrypted")


def test_windows_path_is_cleaned(key):
    name = core.store_file("C:\\Users\\me\\report.txt", b"data", key)

    assert name == "report.txt.encrypted"


@pytest.mark.parametrize("bad", ["", "..", ".", "   ", None])
def test_invalid_filenames_rejected(bad, key):
    with pytest.raises(core.InvalidFilenameError):
        core.store_file(bad, b"data", key)


def test_read_blocks_path_traversal(key):
    core.store_file("a.txt", b"data", key)
    os.makedirs("outside", exist_ok=True)

    # Traversal is reduced to a base name, which is not in the vault
    with pytest.raises(core.VaultFileNotFoundError):
        core.read_file("../outside/x.txt.encrypted", key)


def test_non_vault_file_name_rejected():
    with pytest.raises(core.InvalidFilenameError):
        core.verify_file("notes.txt")


# ---------- Delete ----------

def test_delete_removes_file_and_hash(key):
    name = core.store_file("a.txt", b"1", key)

    core.delete_file(name)

    assert not os.path.exists("vault/" + name)
    assert not os.path.exists("vault/" + name + ".sha256")


def test_delete_missing_file():
    with pytest.raises(core.VaultFileNotFoundError):
        core.delete_file("ghost.txt.encrypted")