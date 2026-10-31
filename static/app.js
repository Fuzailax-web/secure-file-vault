"use strict";

const MAX_SIZE = 10 * 1024 * 1024; // keep in sync with core.MAX_FILE_SIZE
const $ = (id) => document.getElementById(id);

let authMode = "login"; // "login" or "setup"
let statusTimer = null;


/* ---------- Helpers ---------- */

function show(element, visible) {
  element.hidden = !visible;
}

function setStatus(message, kind = "info") {
  const box = $("status");
  clearTimeout(statusTimer);

  if (!message) {
    show(box, false);
    return;
  }

  // textContent only: never insert server or file-name text as HTML
  box.textContent = message;
  box.className = "status " + kind;
  show(box, true);

  if (kind === "ok") {
    statusTimer = setTimeout(() => show(box, false), 6000);
  }
}

async function request(path, options = {}) {
  try {
    return await fetch(path, { credentials: "same-origin", ...options });
  } catch {
    setStatus("Cannot reach the server. Is it still running?", "error");
    return null;
  }
}

async function errorText(response) {
  try {
    const body = await response.json();
    if (typeof body.detail === "string") {
      return body.detail;
    }
  } catch {
    // fall through
  }
  return `Request failed (${response.status}).`;
}

// For vault actions: returns the response only if it succeeded.
// A 401 means the session ended, so go back to the login screen.
async function vaultRequest(path, options = {}) {
  const response = await request(path, options);

  if (!response) {
    return null;
  }

  if (response.status === 401) {
    showAuth("login");
    setStatus("Your session ended. Please log in again.", "error");
    return null;
  }

  if (!response.ok) {
    setStatus(await errorText(response), "error");
    return null;
  }

  return response;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(seconds) {
  return new Date(seconds * 1000).toLocaleString();
}

function stripEncrypted(name) {
  return name.endsWith(".encrypted") ? name.slice(0, -".encrypted".length) : name;
}

function makeCell(text, className, label) {
  const cell = document.createElement("td");
  cell.textContent = text;
  if (className) cell.className = className;
  if (label) cell.dataset.label = label;
  return cell;
}

function makeButton(label, onClick, className) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  if (className) button.className = className;
  button.addEventListener("click", onClick);
  return button;
}


/* ---------- Views ---------- */

function showAuth(mode) {
  authMode = mode;

  $("auth-title").textContent =
    mode === "setup" ? "Create your master password" : "Unlock your vault";

  $("auth-hint").textContent =
    mode === "setup"
      ? "Use at least 8 characters. If you forget it, your files cannot be recovered."
      : "Enter your master password to continue.";

  $("auth-submit").textContent = mode === "setup" ? "Create vault" : "Unlock";

  $("password").autocomplete =
    mode === "setup" ? "new-password" : "current-password";
  $("password").value = "";

  show($("auth-view"), true);
  show($("vault-view"), false);
  show($("logout-btn"), false);
  show($("log-view"), false);
  $("log-btn").textContent = "Show log";
}

async function showVault() {
  show($("auth-view"), false);
  show($("vault-view"), true);
  show($("logout-btn"), true);

  await loadFiles();
}

function renderFiles(files) {
  const body = $("files-body");
  body.replaceChildren();

  show($("empty"), files.length === 0);
  show($("files-table"), files.length > 0);

  for (const file of files) {
    const row = document.createElement("tr");

    row.append(
      makeCell(file.name, "name"),
      makeCell(formatSize(file.size), "", "Size"),
      makeCell(formatDate(file.modified), "", "Added")
    );

    const actions = document.createElement("td");
    actions.className = "actions";
    actions.append(
      makeButton("Verify", () => verifyFile(file.name)),
      makeButton("Download", () => downloadFile(file.name)),
      makeButton("Delete", () => deleteFile(file.name), "danger")
    );

    row.append(actions);
    body.append(row);
  }
}


/* ---------- Actions ---------- */

async function loadFiles() {
  const response = await vaultRequest("/api/files");

  if (response) {
    renderFiles(await response.json());
  }
}

async function verifyFile(name) {
  const response = await vaultRequest(`/api/files/${encodeURIComponent(name)}/verify`);

  if (!response) return;

  const result = await response.json();

  if (result.intact) {
    setStatus(`${name} is intact. The SHA-256 hash matches.`, "ok");
  } else {
    setStatus(`${name} FAILED the integrity check. It may have been modified.`, "error");
  }
}

async function downloadFile(name) {
  const response = await vaultRequest(`/api/files/${encodeURIComponent(name)}/download`);

  if (!response) return;

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);

  const link = document.createElement("a");
  link.href = url;
  link.download = stripEncrypted(name);
  document.body.append(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);

  setStatus(`Decrypted and downloaded ${stripEncrypted(name)}.`, "ok");
}

async function deleteFile(name) {
  if (!window.confirm(`Delete ${name} from the vault? This cannot be undone.`)) {
    return;
  }

  const response = await vaultRequest(`/api/files/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });

  if (response) {
    setStatus(`Deleted ${name}.`, "ok");
    await loadFiles();
  }
}


/* ---------- Event handlers ---------- */

$("auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const password = $("password").value;
  $("password").value = ""; // never leave the password sitting in the page

  const path = authMode === "setup" ? "/api/setup" : "/api/login";

  const response = await request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });

  if (!response) return;

  if (!response.ok) {
    setStatus(await errorText(response), "error");
    return;
  }

  setStatus("");
  await showVault();
});

$("logout-btn").addEventListener("click", async () => {
  await request("/api/logout", { method: "POST" });
  showAuth("login");
  setStatus("You have been logged out.", "info");
});

const fileInput = $("file-input");
const dropzone = $("dropzone");

function updateDropText() {
  const file = fileInput.files[0];
  $("drop-text").textContent = file
    ? `${file.name} (${formatSize(file.size)})`
    : "Choose a file or drop it here (max 10 MB)";
}

fileInput.addEventListener("change", updateDropText);

dropzone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropzone.classList.add("over");
});

dropzone.addEventListener("dragleave", () => dropzone.classList.remove("over"));

dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropzone.classList.remove("over");

  if (event.dataTransfer.files.length > 0) {
    fileInput.files = event.dataTransfer.files;
    updateDropText();
  }
});

$("upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const file = fileInput.files[0];

  if (!file) {
    setStatus("Choose a file first.", "error");
    return;
  }

  if (file.size > MAX_SIZE) {
    setStatus("That file is larger than 10 MB.", "error");
    return;
  }

  const form = new FormData();
  form.append("file", file);

  const response = await vaultRequest("/api/files", { method: "POST", body: form });

  if (response) {
    const result = await response.json();
    setStatus(`Encrypted and stored as ${result.name}.`, "ok");
    fileInput.value = "";
    updateDropText();
    await loadFiles();
  }
});

$("log-btn").addEventListener("click", async () => {
  const view = $("log-view");

  if (!view.hidden) {
    show(view, false);
    $("log-btn").textContent = "Show log";
    return;
  }

  const response = await vaultRequest("/api/logs");

  if (!response) return;

  const result = await response.json();
  view.textContent = result.lines.length
    ? result.lines.slice().reverse().join("\n")
    : "No log entries yet.";

  show(view, true);
  $("log-btn").textContent = "Hide log";
});


/* ---------- Start ---------- */

async function init() {
  const response = await request("/api/status");

  if (!response || !response.ok) return;

  const state = await response.json();

  if (!state.password_set) {
    showAuth("setup");
  } else if (state.logged_in) {
    await showVault();
  } else {
    showAuth("login");
  }
}

init();
