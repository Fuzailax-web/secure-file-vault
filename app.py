"""Secure File Vault - local web API (FastAPI).

Run with:  uvicorn app:app --host 127.0.0.1 --port 8000
Docs at:   http://127.0.0.1:8000/docs
"""

import os
import secrets
import threading
import time
from urllib.parse import quote, urlparse

from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

import core

SESSION_COOKIE = "vault_session"
SESSION_TIMEOUT = 10 * 60      # seconds of inactivity before auto-logout
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 60
LOG_FILE = "vault.log"
LOG_LINES = 100
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

app = FastAPI(title="Secure File Vault", redoc_url=None)

_lock = threading.Lock()
_sessions = {}          # token -> {"key": bytes, "last": float}
_failed_logins = []     # timestamps of recent failed logins


class PasswordBody(BaseModel):
    password: str = Field(max_length=256)


# ---------- Security middleware ----------

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Block cross-site state-changing requests (CSRF defence in depth;
    # the session cookie is also SameSite=Strict).
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host"):
            return JSONResponse(
                {"detail": "Cross-origin request blocked.", "code": "bad_origin"},
                status_code=403,
            )

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    # The auto-generated /docs page loads scripts from a CDN, so it is exempt
    if not request.url.path.startswith(("/docs", "/openapi")):
        response.headers["Content-Security-Policy"] = CSP

    return response


# ---------- Errors ----------

_ERRORS = {
    core.InvalidFilenameError: (400, "invalid_filename"),
    core.FileTooLargeError: (413, "file_too_large"),
    core.VaultFileNotFoundError: (404, "not_found"),
    core.VaultFileExistsError: (409, "already_exists"),
    core.TamperDetectedError: (409, "tamper_detected"),
    core.WrongKeyError: (400, "wrong_key"),
    core.WeakPasswordError: (400, "weak_password"),
    core.PasswordAlreadySetError: (409, "password_already_set"),
}


@app.exception_handler(core.VaultError)
async def vault_error_handler(request: Request, exc: core.VaultError):
    status, code = _ERRORS.get(type(exc), (400, "vault_error"))
    return JSONResponse({"detail": str(exc), "code": code}, status_code=status)


# ---------- Sessions ----------

def _start_session(response: Response, key: bytes):
    token = secrets.token_urlsafe(32)

    with _lock:
        _sessions[token] = {"key": key, "last": time.monotonic()}

    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
    )


def _get_session(request: Request):
    """Return the live session for this request, or None."""
    token = request.cookies.get(SESSION_COOKIE)
    now = time.monotonic()

    with _lock:
        session = _sessions.get(token)

        if session is None:
            return None

        if now - session["last"] > SESSION_TIMEOUT:
            del _sessions[token]
            return None

        session["last"] = now
        return session


def require_session(request: Request):
    session = _get_session(request)

    if session is None:
        raise HTTPException(status_code=401, detail="Not logged in or session expired.")

    return session


def _check_lockout():
    now = time.monotonic()

    with _lock:
        _failed_logins[:] = [t for t in _failed_logins if now - t < LOCKOUT_SECONDS]

        if len(_failed_logins) >= MAX_FAILED_LOGINS:
            raise HTTPException(
                status_code=429,
                detail="Too many failed attempts. Try again in a minute.",
            )


# ---------- Account routes ----------

@app.get("/api/status")
def status(request: Request):
    return {
        "password_set": core.password_is_set(),
        "logged_in": _get_session(request) is not None,
    }


@app.post("/api/setup", status_code=201)
def setup(body: PasswordBody, response: Response):
    core.set_master_password(body.password)
    _start_session(response, core.derive_vault_key(body.password))
    return {"ok": True}


@app.post("/api/login")
def login(body: PasswordBody, response: Response):
    if not core.password_is_set():
        raise HTTPException(status_code=409, detail="No master password yet. Use setup.")

    _check_lockout()

    if not core.check_password(body.password):
        with _lock:
            _failed_logins.append(time.monotonic())
        raise HTTPException(status_code=401, detail="Incorrect password.")

    with _lock:
        _failed_logins.clear()

    _start_session(response, core.derive_vault_key(body.password))
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)

    with _lock:
        _sessions.pop(token, None)

    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


# ---------- Vault routes ----------

@app.get("/api/files")
def list_files(session=Depends(require_session)):
    return core.list_files()


@app.post("/api/files", status_code=201)
def upload_file(file: UploadFile = File(...), session=Depends(require_session)):
    # Read at most one byte over the limit, so huge uploads are never held in memory
    data = file.file.read(core.MAX_FILE_SIZE + 1)
    name = core.store_file(file.filename, data, session["key"])
    return {"name": name}


@app.get("/api/files/{name}/verify")
def verify_file(name: str, session=Depends(require_session)):
    return {"name": name, "intact": core.verify_file(name)}


@app.get("/api/files/{name}/download")
def download_file(name: str, session=Depends(require_session)):
    original_name, data = core.read_file(name, session["key"])

    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(original_name)}"
        },
    )


@app.delete("/api/files/{name}")
def delete_file(name: str, session=Depends(require_session)):
    core.delete_file(name)
    return {"ok": True}


@app.get("/api/logs")
def get_logs(session=Depends(require_session)):
    if not os.path.isfile(LOG_FILE):
        return {"lines": []}

    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
        lines = file.read().splitlines()

    return {"lines": lines[-LOG_LINES:]}

# ---------- Web page ----------

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/style.css", include_in_schema=False)
def stylesheet():
    return FileResponse(os.path.join(STATIC_DIR, "style.css"))


@app.get("/app.js", include_in_schema=False)
def script():
    return FileResponse(os.path.join(STATIC_DIR, "app.js"))
