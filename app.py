import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("LOCKLINE_DATA_DIR", BASE_DIR)).resolve()
STORAGE_DIR = DATA_DIR / "storage"
KEY_FILE = DATA_DIR / ".lockline_demo_key"
INDEX_FILE = STORAGE_DIR / "index.json"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

session_secret = os.environ.get("LOCKLINE_FLASK_SECRET")
if not session_secret or len(session_secret) < 32:
    raise RuntimeError(
        "Set LOCKLINE_FLASK_SECRET to a random secret of at least 32 characters."
    )

app = Flask(__name__)
app.config.update(
    SECRET_KEY=session_secret,
    DATABASE=os.environ.get("LOCKLINE_DATABASE_PATH", str(DATA_DIR / "lockline.sqlite3")),
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("LOCKLINE_COOKIE_SECURE", "true").lower()
    == "true",
)
MAX_FILE_MB = 50
csrf = CSRFProtect(app)


@contextmanager
def get_db_connection():
    connection = sqlite3.connect(app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def init_db():
    database_path = Path(app.config["DATABASE"])
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                username_key TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


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


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user_id = session.get("user_id")
        if not isinstance(user_id, int):
            return redirect(url_for("login"))

        with get_db_connection() as connection:
            user = connection.execute(
                "SELECT id, username FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if user is None:
            session.clear()
            return redirect(url_for("login"))

        g.user = user
        return view(*args, **kwargs)

    return wrapped


@app.after_request
def prevent_private_response_caching(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(413)
def too_large(_error):
    flash(f"File is too large. Maximum size is {MAX_FILE_MB} MB.", "error")
    return redirect(url_for("index"))


@app.route("/", methods=["GET"])
@login_required
def index():
    user_id = g.user["id"]
    files = [
        item
        for item in read_index()
        if item.get("owner_id") == user_id or item.get("recipient_id") == user_id
    ]
    files.sort(key=lambda item: item.get("uploaded_at", ""), reverse=True)
    return render_template(
        "index.html",
        files=files,
        max_file_mb=MAX_FILE_MB,
        username=g.user["username"],
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            flash(
                "Username must be 3–32 characters using letters, numbers, '.', '_' or '-'.",
                "error",
            )
            return render_template("register.html"), 400
        if len(password) < 12 or len(password) > 128:
            flash("Password must be between 12 and 128 characters.", "error")
            return render_template("register.html"), 400

        username_key = username.lower()
        password_hash = generate_password_hash(password)
        try:
            with get_db_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO users (username, username_key, password_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        username,
                        username_key,
                        password_hash,
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    ),
                )
        except sqlite3.IntegrityError:
            flash("That username is already registered.", "error")
            return render_template("register.html"), 409

        flash("Account created. Log in to start transferring files.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username_key = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        with get_db_connection() as connection:
            user = connection.execute(
                "SELECT id, username, password_hash FROM users WHERE username_key = ?",
                (username_key,),
            ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "error")
            return render_template("login.html"), 401

        session.clear()
        session["user_id"] = user["id"]
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    recipient_username = (request.form.get("recipient") or "").strip()

    if not file or not file.filename:
        flash("Choose a file before uploading.", "error")
        return redirect(url_for("index"))

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", recipient_username):
        flash("Enter the username of a registered recipient.", "error")
        return redirect(url_for("index"))

    with get_db_connection() as connection:
        recipient = connection.execute(
            "SELECT id, username FROM users WHERE username_key = ?",
            (recipient_username.lower(),),
        ).fetchone()
    if recipient is None:
        flash("Recipient must be a registered LOCKLINE user.", "error")
        return redirect(url_for("index"))

    original_name = secure_filename(file.filename) or "uploaded_file"
    raw = file.read()
    if not raw:
        flash("The selected file is empty.", "error")
        return redirect(url_for("index"))

    file_id = uuid.uuid4().hex[:12]
    nonce = os.urandom(12)
    aad = original_name.encode("utf-8")
    ciphertext = AESGCM(get_demo_key()).encrypt(nonce, raw, aad)
    blob_path = STORAGE_DIR / f"{file_id}.lockline"
    blob_path.write_bytes(nonce + ciphertext)

    items = read_index()
    items.append(
        {
            "id": file_id,
            "name": original_name,
            "size": len(raw),
            "sender": g.user["username"],
            "recipient": recipient["username"],
            "owner_id": g.user["id"],
            "recipient_id": recipient["id"],
            "uploaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "status": "Encrypted and stored",
        }
    )
    write_index(items)
    flash(f"'{original_name}' uploaded and encrypted for {recipient['username']}.", "success")
    return redirect(url_for("index"))


@app.route("/download/<file_id>", methods=["GET"])
@login_required
def download(file_id):
    if not re.fullmatch(r"[a-f0-9]{12}", file_id):
        abort(404)
    item = next((entry for entry in read_index() if entry.get("id") == file_id), None)
    if not item:
        flash("File not found.", "error")
        return redirect(url_for("index"))
    if g.user["id"] not in (item.get("owner_id"), item.get("recipient_id")):
        abort(404)

    blob_path = STORAGE_DIR / f"{item['id']}.lockline"
    if not blob_path.exists():
        flash("Encrypted file data is missing.", "error")
        return redirect(url_for("index"))

    try:
        blob = blob_path.read_bytes()
        nonce, ciphertext = blob[:12], blob[12:]
        plaintext = AESGCM(get_demo_key()).decrypt(
            nonce, ciphertext, item["name"].encode("utf-8")
        )
    except (InvalidTag, OSError, KeyError, ValueError):
        flash(
            "Decryption or integrity verification failed. The file may be damaged or the key may have changed.",
            "error",
        )
        return redirect(url_for("index"))

    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=item["name"],
        mimetype="application/octet-stream",
    )


@app.route("/health")
def health():
    return {"app": "LOCKLINE basic prototype", "status": "running", "encryption": "AES-256-GCM for stored files"}


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
