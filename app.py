import os
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
KEY_FILE = BASE_DIR / ".lockline_demo_key"
INDEX_FILE = STORAGE_DIR / "index.json"
STORAGE_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("LOCKLINE_FLASK_SECRET", "change-this-demo-secret")
MAX_FILE_MB = 50
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_MB * 1024 * 1024

def get_demo_key():
    """Create/reuse a local 256-bit AES key for this demonstration."""
    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes()
        if len(key) == 32:
            return key
        raise RuntimeError("Invalid demo key file. Delete .lockline_demo_key to create a new one.")
    key = AESGCM.generate_key(bit_length=256)
    KEY_FILE.write_bytes(key)
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass
    return key

def read_index():
    if not INDEX_FILE.exists():
        return []
    try:
        return json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

def write_index(items):
    INDEX_FILE.write_text(json.dumps(items, indent=2), encoding="utf-8")

@app.errorhandler(413)
def too_large(_error):
    flash(f"File is too large. Maximum size is {MAX_FILE_MB} MB.", "error")
    return redirect(url_for("index"))

@app.route("/", methods=["GET"])
def index():
    items = sorted(read_index(), key=lambda item: item.get("uploaded_at", ""), reverse=True)
    return render_template("index.html", files=items, max_file_mb=MAX_FILE_MB)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    sender = (request.form.get("sender") or "Demo Sender").strip()[:80]
    recipient = (request.form.get("recipient") or "Demo Receiver").strip()[:80]

    if not file or not file.filename:
        flash("Choose a file before uploading.", "error")
        return redirect(url_for("index"))

    original_name = secure_filename(file.filename)
    if not original_name:
        original_name = "uploaded_file"
    raw = file.read()
    if not raw:
        flash("The selected file is empty.", "error")
        return redirect(url_for("index"))

    file_id = uuid.uuid4().hex[:12]
    nonce = os.urandom(12)
    # The filename is included as authenticated metadata, so it cannot be silently changed.
    aad = original_name.encode("utf-8")
    ciphertext = AESGCM(get_demo_key()).encrypt(nonce, raw, aad)
    blob_path = STORAGE_DIR / f"{file_id}.lockline"
    blob_path.write_bytes(nonce + ciphertext)

    items = read_index()
    items.append({
        "id": file_id,
        "name": original_name,
        "size": len(raw),
        "sender": sender or "Demo Sender",
        "recipient": recipient or "Demo Receiver",
        "uploaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "Encrypted and stored"
    })
    write_index(items)
    flash(f"'{original_name}' uploaded. The stored file is AES-256-GCM encrypted.", "success")
    return redirect(url_for("index"))

@app.route("/download/<file_id>", methods=["GET"])
def download(file_id):
    item = next((entry for entry in read_index() if entry.get("id") == file_id), None)
    if not item:
        flash("File not found.", "error")
        return redirect(url_for("index"))

    blob_path = STORAGE_DIR / f"{file_id}.lockline"
    if not blob_path.exists():
        flash("Encrypted file data is missing.", "error")
        return redirect(url_for("index"))

    try:
        blob = blob_path.read_bytes()
        nonce, ciphertext = blob[:12], blob[12:]
        plaintext = AESGCM(get_demo_key()).decrypt(nonce, ciphertext, item["name"].encode("utf-8"))
    except Exception:
        flash("Decryption or integrity verification failed. The file may be damaged or the key may have changed.", "error")
        return redirect(url_for("index"))

    from io import BytesIO
    return send_file(BytesIO(plaintext), as_attachment=True, download_name=item["name"], mimetype="application/octet-stream")

@app.route("/health")
def health():
    return {"app": "LOCKLINE basic prototype", "status": "running", "encryption": "AES-256-GCM for stored files"}

if __name__ == "__main__":
    # Use 0.0.0.0 to allow devices on the same trusted Wi-Fi to open the demo.
    # This is HTTP, not production TLS. Use only on a trusted local network.
    app.run(host="0.0.0.0", port=5000, debug=False)
