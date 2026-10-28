import os
import secrets
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("LOCKLINE_FLASK_SECRET", secrets.token_hex(32))

import app as lockline_app


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        data_dir = Path(self.temp_dir.name)
        self.storage_patch = patch.object(lockline_app, "STORAGE_DIR", data_dir / "storage")
        self.index_patch = patch.object(lockline_app, "INDEX_FILE", data_dir / "storage" / "index.json")
        self.key_patch = patch.object(lockline_app, "KEY_FILE", data_dir / ".lockline_demo_key")
        self.storage_patch.start()
        self.index_patch.start()
        self.key_patch.start()
        lockline_app.STORAGE_DIR.mkdir(parents=True)
        lockline_app.app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
            DATABASE=str(data_dir / "users.sqlite3"),
            SESSION_COOKIE_SECURE=False,
        )
        lockline_app.init_db()
        self.client = lockline_app.app.test_client()

    def tearDown(self):
        self.key_patch.stop()
        self.index_patch.stop()
        self.storage_patch.stop()
        self.temp_dir.cleanup()

    def register(self, username, password="correct-horse-battery"):
        return self.client.post(
            "/register",
            data={"username": username, "password": password},
            follow_redirects=False,
        )

    def login(self, username, password="correct-horse-battery"):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=False,
        )

    def upload(self, recipient="bob"):
        return self.client.post(
            "/upload",
            data={
                "recipient": recipient,
                "file": (BytesIO(b"private transfer payload"), "sample.txt"),
            },
            content_type="multipart/form-data",
        )

    def test_registration_succeeds_and_stores_password_hash(self):
        response = self.register("alice")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")
        with lockline_app.get_db_connection() as connection:
            user = connection.execute(
                "SELECT username, password_hash FROM users WHERE username_key = ?",
                ("alice",),
            ).fetchone()
        self.assertEqual(user["username"], "alice")
        self.assertNotEqual(user["password_hash"], "correct-horse-battery")
        self.assertTrue(user["password_hash"].startswith("scrypt:"))

    def test_duplicate_registration_is_rejected_case_insensitively(self):
        self.register("alice")

        response = self.register("ALICE")

        self.assertEqual(response.status_code, 409)
        self.assertIn(b"already registered", response.data)

    def test_correct_login_succeeds(self):
        self.register("alice")

        response = self.login("alice")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_incorrect_login_fails_with_generic_message(self):
        self.register("alice")

        response = self.login("alice", "wrong-password-value")

        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid username or password.", response.data)

    def test_logout_clears_session(self):
        self.register("alice")
        self.login("alice")

        response = self.client.post("/logout")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")
        self.assertEqual(self.client.get("/").headers["Location"], "/login")

    def test_unauthenticated_dashboard_redirects_to_login(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_unauthenticated_upload_and_download_are_denied(self):
        upload_response = self.upload()
        download_response = self.client.get("/download/0123456789ab")

        self.assertEqual(upload_response.status_code, 302)
        self.assertEqual(upload_response.headers["Location"], "/login")
        self.assertEqual(download_response.status_code, 302)
        self.assertEqual(download_response.headers["Location"], "/login")
        self.assertEqual(list(lockline_app.STORAGE_DIR.glob("*.lockline")), [])

    def test_unregistered_recipient_is_rejected(self):
        self.register("alice")
        self.login("alice")

        response = self.upload("nobody")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        self.assertEqual(list(lockline_app.STORAGE_DIR.glob("*.lockline")), [])

    def test_only_sender_and_recipient_can_access_private_file(self):
        self.register("alice")
        self.register("bob")
        self.register("charlie")
        self.login("alice")
        upload_response = self.upload()
        self.assertEqual(upload_response.status_code, 302)
        item = lockline_app.read_index()[-1]
        self.client.post("/logout")
        self.login("charlie")

        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertNotIn(item["name"].encode(), self.client.get("/").data)
        self.assertEqual(self.client.get(f"/download/{item['id']}").status_code, 404)

    def test_aes_gcm_upload_and_recipient_download_round_trip(self):
        self.register("alice")
        self.register("bob")
        self.login("alice")

        response = self.upload("bob")
        self.assertEqual(response.status_code, 302)
        item = lockline_app.read_index()[-1]
        blob = (lockline_app.STORAGE_DIR / f"{item['id']}.lockline").read_bytes()
        self.assertNotIn(b"private transfer payload", blob)

        self.client.post("/logout")
        self.login("bob")
        download_response = self.client.get(f"/download/{item['id']}")

        self.assertEqual(download_response.status_code, 200)
        self.assertEqual(download_response.data, b"private transfer payload")

    def test_post_forms_require_csrf_tokens(self):
        lockline_app.app.config["WTF_CSRF_ENABLED"] = True

        response = self.client.post(
            "/register", data={"username": "alice", "password": "correct-horse-battery"}
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"CSRF", response.data)


if __name__ == "__main__":
    unittest.main()
