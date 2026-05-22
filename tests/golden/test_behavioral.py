"""Behavioral assertions for endpoints that cannot be golden-snapshotted.

- Registration/verification is a deliberate behavior change (mandatory
  verification in the new stack).
- HTML pages are checked for status + key content, not byte-identity: a
  SHA-256 of rendered HTML is too brittle across a Django major-version jump.
"""
import re
import uuid

import requests


# --- web login through nginx (CSRF) ---

def test_web_login_through_nginx_succeeds(base_url):
    # Full browser-style login: GET sets the csrftoken cookie, the POST sends
    # the form token plus an Origin header. Regression test for the nginx
    # Host-header / Django CSRF Origin-check mismatch (port-stripped Host).
    # Uses an isolated session so the resulting login cookie does not leak
    # into other tests on the shared session.
    session = requests.Session()
    try:
        page = session.get(base_url + "/login/", timeout=30)
        assert page.status_code == 200
        match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page.text)
        assert match, "csrfmiddlewaretoken not found in the login form"
        resp = session.post(base_url + "/login/", data={
            "csrfmiddlewaretoken": match.group(1),
            "username": "alice", "password": "alicepass123",
        }, headers={"Origin": base_url, "Referer": base_url + "/login/"},
           allow_redirects=False, timeout=30)
        assert resp.status_code == 302, "browser login failed (got %s)" % resp.status_code
    finally:
        session.close()


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
    assert "ข้อมูลผู้ใช้ E-Tipitaka" in resp.text


def test_login_page_renders(http, base_url):
    resp = http.get(base_url + "/login/", timeout=30)
    assert resp.status_code == 200
    assert "<h1>เข้าสู่ระบบ</h1>" in resp.text


def test_signup_page_renders(http, base_url):
    resp = http.get(base_url + "/signup/", timeout=30)
    assert resp.status_code == 200
    assert "<h1>สมัครสมาชิก</h1>" in resp.text


def test_validate_page_renders(http, base_url):
    resp = http.get(base_url + "/signup/validate/", timeout=30)
    assert resp.status_code == 200
    assert "ยืนยันอีเมลของคุณ" in resp.text


def test_login_post_without_csrf_is_forbidden(http, base_url):
    # A cross-site POST with no CSRF token is rejected before the view runs.
    resp = http.post(base_url + "/login/",
                     data={"username": "alice", "password": "wrongpass"},
                     timeout=30)
    assert resp.status_code == 403


def test_password_reset_pages_use_project_templates(http, base_url):
    # The four password-reset pages must render the project's base.html, not
    # Django admin's fallback registration/* templates.
    pages = [
        ("/password_reset/", "รีเซ็ตรหัสผ่านของคุณ"),
        ("/password_reset/done/", "ตรวจสอบอีเมลของคุณ"),
        ("/reset/done/", "รีเซ็ตรหัสผ่านเสร็จสมบูรณ์"),
        ("/reset/baduid/badtoken/", "ตั้งรหัสผ่านใหม่"),
    ]
    for path, marker in pages:
        resp = http.get(base_url + path, timeout=30)
        assert resp.status_code == 200, "%s -> %s" % (path, resp.status_code)
        assert marker in resp.text, "%s missing project marker %r" % (path, marker)
        assert "Django site admin" not in resp.text, "%s still admin-styled" % path
