
import auth


def test_setup_password(tmp_path, monkeypatch):
    password_file = tmp_path / "password.hash"

    monkeypatch.setattr(auth, "PASSWORD_FILE", str(password_file))
    monkeypatch.setattr(auth, "getpass", lambda _: "TestPassword123")

    result = auth.setup_password()

    assert result == "TestPassword123"
    assert password_file.exists()


def test_login_success(tmp_path, monkeypatch):
    password_file = tmp_path / "password.hash"

    monkeypatch.setattr(auth, "PASSWORD_FILE", str(password_file))
    monkeypatch.setattr(auth, "getpass", lambda _: "TestPassword123")

    auth.setup_password()

    result = auth.login()

    assert result == "TestPassword123"


def test_login_wrong_password(tmp_path, monkeypatch):
    password_file = tmp_path / "password.hash"

    monkeypatch.setattr(auth, "PASSWORD_FILE", str(password_file))

    monkeypatch.setattr(
        auth,
        "getpass",
        lambda _: "CorrectPassword123"
    )

    auth.setup_password()

    monkeypatch.setattr(
        auth,
        "getpass",
        lambda _: "WrongPassword123"
    )

    result = auth.login()

    assert result is None