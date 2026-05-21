"""Behavioral assertions for endpoints that cannot be golden-snapshotted.

- Registration/verification is a deliberate behavior change (mandatory
  verification in the new stack).
- HTML pages are checked for status + key content, not byte-identity: a
  SHA-256 of rendered HTML is too brittle across a Django major-version jump.
"""
import uuid


# --- registration / email verification ---

def test_registration_creates_pending_account_then_login_blocked(http, base_url):
    username = "probe_" + uuid.uuid4().hex[:10]
    email = username + "@example.com"

    reg = http.post(base_url + "/rest-auth/registration/", data={
        "email": email, "username": username,
        "password1": "pw12345678", "password2": "pw12345678",
    }, timeout=30)
    assert reg.status_code == 201, reg.text

    # Mandatory verification: login must be refused until verified.
    login = http.post(base_url + "/rest-auth/login/", data={
        "username": username, "password": "pw12345678",
    }, timeout=30)
    assert login.status_code == 400


def test_registration_rejects_duplicate_username(http, base_url):
    # 'alice' exists from seed_golden.
    reg = http.post(base_url + "/rest-auth/registration/", data={
        "email": "dup@example.com", "username": "alice",
        "password1": "pw12345678", "password2": "pw12345678",
    }, timeout=30)
    assert reg.status_code == 400
    assert "username" in reg.json()


def test_verify_email_rejects_garbage_token(http, base_url):
    resp = http.post(base_url + "/rest-auth/registration/verify-email/",
                     data={"key": "not-a-real-token"}, timeout=30)
    assert resp.status_code == 400


# --- HTML pages: status + key content (not byte-identity) ---

def test_index_page_renders(http, base_url):
    resp = http.get(base_url + "/", timeout=30)
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("Content-Type", "")
    assert "E-Tipitaka User Data" in resp.text


def test_login_page_renders(http, base_url):
    resp = http.get(base_url + "/login/", timeout=30)
    assert resp.status_code == 200
    assert "<h1>Login</h1>" in resp.text


def test_signup_page_renders(http, base_url):
    resp = http.get(base_url + "/signup/", timeout=30)
    assert resp.status_code == 200
    assert "<h1>Registration</h1>" in resp.text


def test_validate_page_renders(http, base_url):
    resp = http.get(base_url + "/signup/validate/", timeout=30)
    assert resp.status_code == 200
    assert "Validate your e-mail" in resp.text


def test_login_post_without_csrf_is_forbidden(http, base_url):
    # A cross-site POST with no CSRF token is rejected before the view runs.
    resp = http.post(base_url + "/login/",
                     data={"username": "alice", "password": "wrongpass"},
                     timeout=30)
    assert resp.status_code == 403
