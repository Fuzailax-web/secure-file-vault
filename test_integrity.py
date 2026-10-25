from integrity import calculate_hash, save_hash, load_hash, verify_hash


def test_calculate_hash(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Secure File Vault")

    file_hash = calculate_hash(test_file)

    assert len(file_hash) == 64


def test_save_and_load_hash(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Test data")

    file_hash = calculate_hash(test_file)

    save_hash(test_file, file_hash)

    loaded_hash = load_hash(test_file)

    assert loaded_hash == file_hash


def test_verify_hash_success(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Secure data")

    file_hash = calculate_hash(test_file)

    result = verify_hash(
        test_file,
        file_hash
    )

    assert result is True


def test_verify_hash_failure(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Original data")

    file_hash = calculate_hash(test_file)

    test_file.write_text("Tampered data")

    result = verify_hash(
        test_file,
        file_hash
    )

    assert result is False