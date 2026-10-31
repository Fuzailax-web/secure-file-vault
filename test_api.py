import pytest
from fastapi.testclient import TestClient

import app as app_module
import core

PASSWORD = "CorrectHorse1"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Fresh folder and fresh in-memory state for every test."""
    monkeypatch.chdir(tmp_path)
    app_module._sessions.clear()
    app_module._failed_logins.clear()


@pytest.fixture
def client():
    return TestClient(app_module.app)


@pytest.fixture
def logged_in(client):
    response = client.post("/api/setup", json={"password": PASSWORD})
    assert response.status_code == 201
    return client


def upload(client, name="notes.txt", data=b"hello vault"):
    return client.post("/api/files", files={"file": (name, data)})


# ---------- Account ----------

def test_status_before_setup(client):
    body = client.get("/api/status").json()

    assert body == {"password_set": False, "logged_in": False}


def test_setup_logs_in(logged_in):
    body = logged_in.get("/api/status").json()

    assert body == {"password_set": True, "logged_in": True}


def test_setup_twice_rejected(logged_in):
    response = logged_in.post("/api/setup", json={"password": "AnotherPass22"})

    assert response.status_code == 409
    assert response.json()["code"] == "password_already_set"


def test_weak_password_rejected(client):
    response = client.post("/api/setup", json={"password": "short"})

    assert response.status_code == 400
    assert response.json()["code"] == "weak_password"


def test_login_wrong_password(logged_in):
    logged_in.post("/api/logout")

    response = logged_in.post("/api/login", json={"password": "wrong-password"})

    assert response.status_code == 401


def test_login_correct_password(logged_in):
    logged_in.post("/api/logout")

    response = logged_in.post("/api/login", json={"password": PASSWORD})

    assert response.status_code == 200
    assert logged_in.get("/api/status").json()["logged_in"] is True


def test_login_before_setup(client):
    response = client.post("/api/login", json={"password": PASSWORD})

    assert response.status_code == 409


def test_logout_ends_session(logged_in):
    logged_in.post("/api/logout")

    assert logged_in.get("/api/files").status_code == 401


def test_session_cookie_flags(client):
    response = client.post("/api/setup", json={"password": PASSWORD})
    cookie = response.headers["set-cookie"].lower()

    assert "httponly" in cookie
    assert "samesite=strict" in cookie


def test_session_expires(logged_in, monkeypatch):
    monkeypatch.setattr(app_module, "SESSION_TIMEOUT", -1)

    assert logged_in.get("/api/files").status_code == 401


def test_lockout_after_failed_logins(logged_in):
    logged_in.post("/api/logout")

    for _ in range(5):
        response = logged_in.post("/api/login", json={"password": "wrong-password"})
        assert response.status_code == 401

    # Even the correct password is refused while locked out
    response = logged_in.post("/api/login", json={"password": PASSWORD})

    assert response.status_code == 429


# ---------- Access control ----------

@pytest.mark.parametrize("method,url", [
    ("get", "/api/files"),
    ("get", "/api/logs"),
    ("get", "/api/files/a.txt.encrypted/verify"),
    ("get", "/api/files/a.txt.encrypted/download"),
    ("delete", "/api/files/a.txt.encrypted"),
])
def test_routes_require_login(client, method, url):
    response = getattr(client, method)(url)

    assert response.status_code == 401


def test_upload_requires_login(client):
    assert upload(client).status_code == 401


# ---------- Files ----------

def test_upload_list_download_roundtrip(logged_in):
    response = upload(logged_in)

    assert response.status_code == 201
    assert response.json() == {"name": "notes.txt.encrypted"}

    files = logged_in.get("/api/files").json()
    assert [f["name"] for f in files] == ["notes.txt.encrypted"]

    download = logged_in.get("/api/files/notes.txt.encrypted/download")

    assert download.status_code == 200
    assert download.content == b"hello vault"
    assert "notes.txt" in download.headers["content-disposition"]


def test_stored_data_is_encrypted_on_disk(logged_in):
    upload(logged_in, data=b"plain secret text")

    with open("vault/notes.txt.encrypted", "rb") as file:
        stored = file.read()

    assert b"plain secret text" not in stored


def test_duplicate_upload_rejected(logged_in):
    upload(logged_in)

    response = upload(logged_in)

    assert response.status_code == 409
    assert response.json()["code"] == "already_exists"


def test_upload_too_large(logged_in, monkeypatch):
    monkeypatch.setattr(core, "MAX_FILE_SIZE", 10)

    response = upload(logged_in, data=b"x" * 11)

    assert response.status_code == 413


def test_upload_filename_is_cleaned(logged_in):
    response = upload(logged_in, name="../../evil.txt")

    assert response.json() == {"name": "evil.txt.encrypted"}


def test_verify_intact_then_tampered(logged_in):
    upload(logged_in)

    ok = logged_in.get("/api/files/notes.txt.encrypted/verify").json()
    assert ok["intact"] is True

    with open("vault/notes.txt.encrypted", "ab") as file:
        file.write(b"tampered")

    bad = logged_in.get("/api/files/notes.txt.encrypted/verify").json()
    assert bad["intact"] is False


def test_download_tampered_file_blocked(logged_in):
    upload(logged_in)

    with open("vault/notes.txt.encrypted", "ab") as file:
        file.write(b"tampered")

    response = logged_in.get("/api/files/notes.txt.encrypted/download")

    assert response.status_code == 409
    assert response.json()["code"] == "tamper_detected"


def test_download_missing_file(logged_in):
    response = logged_in.get("/api/files/ghost.txt.encrypted/download")

    assert response.status_code == 404


def test_download_path_traversal_blocked(logged_in):
    response = logged_in.get("/api/files/..%2F..%2Fetc%2Fpasswd/download")

    assert response.status_code in (400, 404)


def test_non_vault_name_rejected(logged_in):
    response = logged_in.get("/api/files/notes.txt/verify")

    assert response.status_code == 400


def test_delete_file(logged_in):
    upload(logged_in)

    response = logged_in.delete("/api/files/notes.txt.encrypted")

    assert response.status_code == 200
    assert logged_in.get("/api/files").json() == []


def test_delete_missing_file(logged_in):
    response = logged_in.delete("/api/files/ghost.txt.encrypted")

    assert response.status_code == 404


def test_logs_endpoint(logged_in, tmp_path):
    (tmp_path / "vault.log").write_text("line one\nline two\n")

    lines = logged_in.get("/api/logs").json()["lines"]

    assert lines == ["line one", "line two"]


# ---------- Web security ----------

def test_cross_origin_post_blocked(client):
    response = client.post(
        "/api/login",
        json={"password": PASSWORD},
        headers={"Origin": "http://evil.example"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "bad_origin"


def test_security_headers_present(client):
    headers = client.get("/api/status").headers

    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["cache-control"] == "no-store"

# ---------- Web page ----------

@pytest.mark.parametrize("path,kind", [
    ("/", "text/html"),
    ("/style.css", "text/css"),
    ("/app.js", "javascript"),
])
def test_static_files_served(client, path, kind):
    response = client.get(path)

    assert response.status_code == 200
    assert kind in response.headers["content-type"]


def test_content_security_policy(client):
    csp = client.get("/").headers["content-security-policy"]

    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
