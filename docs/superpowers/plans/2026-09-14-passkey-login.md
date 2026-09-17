# Passkey Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let E-Tipitaka users sign in with passkeys (WebAuthn) from the iOS app, Android app and web; let existing users link a passkey to their account; let new users sign up with passkey + verified email; recover lost passkeys through the password-reset email.

**Architecture:** `webauthn==3.0.0` (py_webauthn) does the cryptographic verification. A small in-house module in `app/user_data/` owns ceremony state (single-use challenges in PostgreSQL), account rules and persistence. Thin DRF views expose a JSON API for native apps and the web pages; plain Django views (CSRF-protected) handle browser-session login and recovery. Vanilla JS in `app/assets/` drives `navigator.credentials` on the web.

**Tech Stack:** Django 5.2, DRF 3.16, django-oauth-toolkit 3.4.1, PostgreSQL 16, py_webauthn 3.0.0 (+ cbor2, cryptography), pytest-django, golden HTTP harness, nginx, vanilla JS.

**Spec:** `docs/superpowers/specs/2026-09-14-passkey-login-design.md`. **Branch:** `feat/passkey-login` (already created; the spec is committed there).

---

## Conventions for every task

- Run everything through Docker Compose from the repo root (`/Volumes/SeagateBackup/Works/watnapahpong/data-etipitaka`). The stack is already up (`docker compose ps` shows `web`, `db`, `nginx`, `mcp`).
- Targeted unit runs skip the coverage gate (it fails on partial runs):
  `docker compose exec -T web python -m pytest user_data/tests/<file>.py -v --no-cov`
- The full suite (with the 90% gate) runs in the last task:
  `docker compose exec -T web python -m pytest`
- Test paths are relative to `app/` because the container's working directory is `/home/app/web` (= `app/`).
- Python code style: match `app/user_data/*.py` — module docstring, function-based DRF views, `gettext as _`, 4-space indent, short comments only where the reason is not obvious.
- **Never** use `_` as a throwaway variable in modules that import `gettext as _`; use `_created`, `_options`, `_i`.
- Binary model fields come back from PostgreSQL as `memoryview`: always wrap with `bytes(...)` before comparing or passing to py_webauthn.
- Commit after each task with a Conventional Commit message ending in:
  `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`

## Decisions made while planning (small refinements of the spec)

1. `PASSKEY_EXPECTED_ORIGINS` is a function, `passkey_config.expected_origins()`, evaluated at call time so tests can change settings. Same for `rp_id()` / `web_origin()`.
2. Module split: `passkey_config.py`, `passkey_challenges.py`, `passkey_service.py` (ceremonies), `passkey_manage.py` (list/rename/delete/remove password), `account_tokens.py` (revocation), `passkey_views.py` (DRF JSON), `passkey_web_views.py` (browser session + security page), `wellknown_views.py`, `recovery.py`. Page JS: `passkey.js` (shared) + `passkey_login.js`, `passkey_signup.js`, `account_security.js`, `passkey_recover.js`.
3. `/.well-known/assetlinks.json` returns a JSON 404 body (not Django's HTML 404) so the golden snapshot is stable under `DEBUG`.
4. All lockout-guard 409s use one message: "Your account must keep at least one way to sign in."
5. AAGUID `fbfc3007-…` is labelled "Apple Passwords" (current name in the passkeydeveloper AAGUID list).
6. `AccountIdentitySerializer` is extracted from `RegisterSerializer` and gains Django's `UnicodeUsernameValidator`, shared by password and passkey signup.
7. The DRF throttle is `UserRateThrottle`-based (per user when signed in, per IP otherwise) so password guessing through step-up is also metered.
8. The e2e script runs *inside* the web container (`python - < tests/passkey_e2e.py`) so it can reuse the unit tests' software authenticator and create/delete its own throwaway accounts.

## File map

| File | Status | Responsibility |
|---|---|---|
| `app/requirements.txt` | modify | pin `webauthn==3.0.0` |
| `app/etipitaka_auth/settings.py` | modify | `PASSKEY_*` settings, `passkey` throttle rate |
| `app/etipitaka_auth/urls.py` | modify | all new routes |
| `app/user_data/models.py` | modify | `Passkey`, `PasskeyUserHandle`, `WebAuthnChallenge` |
| `app/user_data/migrations/0005_passkeys.py` | create (generated) | schema |
| `app/user_data/passkey_config.py` | create | RP ID, web origin, Android origins |
| `app/user_data/passkey_challenges.py` | create | single-use challenge rows |
| `app/user_data/serializers.py` | modify | `AccountIdentitySerializer` |
| `app/user_data/passkey_service.py` | create | register / login / step-up / signup / recover ceremonies |
| `app/user_data/account_tokens.py` | create | revoke DRF + OAuth tokens |
| `app/user_data/passkey_manage.py` | create | list / rename / delete / remove password |
| `app/user_data/passkey_views.py` | create | DRF JSON API |
| `app/user_data/passkey_web_views.py` | create | `/login/passkey/`, `/account/security/` |
| `app/user_data/wellknown_views.py` | create | AASA + assetlinks |
| `app/user_data/recovery.py` | create | reset form, token generator, confirm view, recovery passkey endpoints |
| `app/templates/email/passkey_added.txt` | create | notification email |
| `app/templates/registration/password_reset_email.txt` | create | recovery email |
| `app/templates/registration/password_reset_confirm.html` | modify | passkey recovery button |
| `app/templates/base.html` | modify | `[hidden]` rule, i18n key, navbar link |
| `app/templates/forms/login_form.html`, `app/templates/login.html` | modify | passkey sign-in |
| `app/templates/signup.html` | modify | passkey signup + password fallback |
| `app/templates/account_security.html` | create | security page |
| `app/assets/passkey.js`, `passkey_login.js`, `passkey_signup.js`, `account_security.js`, `passkey_recover.js` | create | browser ceremonies |
| `app/locale/th/LC_MESSAGES/django.po` / `.mo` | modify | Thai strings |
| `nginx/nginx.conf`, `deploy.sh` | modify | rate-limit zone, AASA health check |
| `app/user_data/tests/soft_authenticator.py` | create | software WebAuthn authenticator |
| `app/user_data/tests/conftest.py` | modify | pinned RP settings, fixtures, helpers |
| `app/user_data/tests/test_passkey_*.py`, `test_account_tokens.py`, `test_recovery.py`, `test_wellknown.py`, `test_serializers.py` | create/modify | unit tests |
| `tests/golden/normalize.py`, `test_normalize.py`, `endpoints.py`, `snapshots/*.json`, `README.md` | modify | golden cases |
| `tests/passkey_e2e.py` | create | end-to-end check |
| `docs/passkeys-client-integration.md` | create | native client + operator guide |

---

### Task 1: Dependency, settings and relying-party config

**Files:**
- Modify: `app/requirements.txt`
- Modify: `app/etipitaka_auth/settings.py` (REST_FRAMEWORK block ~line 71; after the `OAUTH2_PROVIDER` block ~line 131; pytest block at end of file)
- Create: `app/user_data/passkey_config.py`
- Test: `app/user_data/tests/test_passkey_config.py`

- [ ] **Step 1: Add the dependency and rebuild the web image**

Append to `app/requirements.txt`:

```
webauthn==3.0.0
```

Run:
```bash
docker compose build web && docker compose up -d web
docker compose exec -T web python -c "import webauthn, cbor2, cryptography; print(webauthn.__version__, cryptography.__version__)"
```
Expected: `3.0.0 50.x.x` (any `cryptography>=49`). If PyPI is slow, retry the build; do not change the pin. If the resolver reports a conflict with django-oauth-toolkit's `cryptography`, pin `webauthn==2.8.0` instead (same API) and note it in the commit message.

- [ ] **Step 2: Write the failing test**

Create `app/user_data/tests/test_passkey_config.py`:

```python
import base64

import pytest

from user_data import passkey_config


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def test_rp_id_defaults_to_issuer_host(settings):
    settings.OAUTH_ISSUER_URL = 'https://data.etipitaka.com'
    settings.PASSKEY_RP_ID = ''
    assert passkey_config.rp_id() == 'data.etipitaka.com'


def test_rp_id_override(settings):
    settings.PASSKEY_RP_ID = 'localhost'
    assert passkey_config.rp_id() == 'localhost'


def test_web_origin_defaults_to_issuer(settings):
    settings.OAUTH_ISSUER_URL = 'https://data.etipitaka.com'
    settings.PASSKEY_WEB_ORIGIN = ''
    assert passkey_config.web_origin() == 'https://data.etipitaka.com'


def test_web_origin_override_drops_trailing_slash(settings):
    settings.PASSKEY_WEB_ORIGIN = 'http://localhost:1338/'
    assert passkey_config.web_origin() == 'http://localhost:1338'


def test_android_origin_from_colon_hex_fingerprint():
    fingerprint = ':'.join(['AB'] * 32)
    assert passkey_config.android_origin(fingerprint) == (
        'android:apk-key-hash:' + _b64url(bytes([0xAB]) * 32))


@pytest.mark.parametrize('fingerprint', ['AB:CD', 'not-hex'])
def test_android_origin_rejects_non_sha256_fingerprint(fingerprint):
    with pytest.raises(ValueError):
        passkey_config.android_origin(fingerprint)


def test_expected_origins_lists_web_then_android(settings):
    settings.PASSKEY_WEB_ORIGIN = 'https://data.etipitaka.com'
    settings.PASSKEY_ANDROID_CERT_SHA256 = [':'.join(['01'] * 32)]
    assert passkey_config.expected_origins() == [
        'https://data.etipitaka.com',
        'android:apk-key-hash:' + _b64url(bytes([1]) * 32)]


def test_settings_defaults(settings):
    assert settings.PASSKEY_RP_NAME == 'E-Tipitaka'
    assert settings.PASSKEY_CHALLENGE_TTL == 300
    assert 'A6DJDJ7527.com.watnapp.E-Tipitaka-Plus' in settings.PASSKEY_IOS_APP_IDS
    assert 'passkey' in settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']
```

- [ ] **Step 3: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_config.py -v --no-cov`
Expected: FAIL — `ImportError: cannot import name 'passkey_config'`.

- [ ] **Step 4: Add the settings**

In `app/etipitaka_auth/settings.py`, change the throttle rates:

```python
    'DEFAULT_THROTTLE_RATES': {
        'login': '10/min',
        'passkey': '20/min',
    },
```

Directly after the closing `}` of `OAUTH2_PROVIDER = {...}` add:

```python

# Passkeys (WebAuthn). The relying-party ID and web origin default to the
# public issuer; local browser testing overrides both (localhost) through the
# gitignored docker-compose.override.yml, never the tracked .env. Android
# values are set the same way in production. See
# docs/superpowers/specs/2026-09-14-passkey-login-design.md.
def _env_list(name, default=''):
    return [v.strip() for v in os.environ.get(name, default).split(',') if v.strip()]


PASSKEY_RP_ID = os.environ.get('PASSKEY_RP_ID', '')
PASSKEY_WEB_ORIGIN = os.environ.get('PASSKEY_WEB_ORIGIN', '')
PASSKEY_RP_NAME = 'E-Tipitaka'
PASSKEY_IOS_APP_IDS = _env_list('PASSKEY_IOS_APP_IDS', 'A6DJDJ7527.com.watnapp.E-Tipitaka-Plus')
PASSKEY_ANDROID_PACKAGE = os.environ.get('PASSKEY_ANDROID_PACKAGE', '')
PASSKEY_ANDROID_CERT_SHA256 = _env_list('PASSKEY_ANDROID_CERT_SHA256')
PASSKEY_CHALLENGE_TTL = 300  # seconds
```

In the pytest block at the end of the file, after the `login` line add:

```python
    REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['passkey'] = None
```

- [ ] **Step 5: Write the config module**

Create `app/user_data/passkey_config.py`:

```python
"""Relying-party configuration for passkeys, read from settings at call time."""
import base64
from urllib.parse import urlparse

from django.conf import settings


def rp_id():
    return settings.PASSKEY_RP_ID or urlparse(settings.OAUTH_ISSUER_URL).hostname


def web_origin():
    return (settings.PASSKEY_WEB_ORIGIN or settings.OAUTH_ISSUER_URL).rstrip('/')


def android_origin(fingerprint):
    """Colon-hex SHA-256 signing-cert fingerprint -> WebAuthn origin of the Android app."""
    raw = bytes.fromhex(fingerprint.replace(':', '').strip())
    if len(raw) != 32:
        raise ValueError('expected a SHA-256 certificate fingerprint')
    return 'android:apk-key-hash:' + base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def expected_origins():
    # iOS native apps report https://<rp id>, so the web origin covers them.
    return [web_origin()] + [android_origin(fp) for fp in settings.PASSKEY_ANDROID_CERT_SHA256]
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_config.py -v --no-cov`
Expected: 9 passed.

- [ ] **Step 7: Commit**

```bash
git add app/requirements.txt app/etipitaka_auth/settings.py app/user_data/passkey_config.py app/user_data/tests/test_passkey_config.py
git commit -m "$(cat <<'EOF'
feat(passkey): add webauthn dependency and relying-party config

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Passkey models and migration

**Files:**
- Modify: `app/user_data/models.py`
- Create (generated): `app/user_data/migrations/0005_passkeys.py`
- Test: `app/user_data/tests/test_passkey_models.py`

- [ ] **Step 1: Write the failing test**

Create `app/user_data/tests/test_passkey_models.py`:

```python
import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from user_data.models import Passkey, PasskeyUserHandle, WebAuthnChallenge

pytestmark = pytest.mark.django_db


def _passkey(user, credential_id='cred-1'):
    return Passkey.objects.create(user=user, credential_id=credential_id,
                                  public_key=b'\x01\x02', name='Phone')


def test_passkey_defaults(alice):
    passkey = _passkey(alice)
    passkey.refresh_from_db()
    assert passkey.sign_count == 0
    assert passkey.transports == []
    assert passkey.backed_up is False
    assert passkey.aaguid == ''
    assert passkey.last_used_at is None
    assert passkey.created_at is not None
    assert bytes(passkey.public_key) == b'\x01\x02'
    assert list(alice.passkeys.all()) == [passkey]


def test_passkey_credential_id_is_unique(alice, bob):
    _passkey(alice)
    with pytest.raises(IntegrityError), transaction.atomic():
        _passkey(bob)


def test_user_handle_one_per_user(alice):
    PasskeyUserHandle.objects.create(user=alice, handle=b'h' * 32)
    with pytest.raises(IntegrityError), transaction.atomic():
        PasskeyUserHandle.objects.create(user=alice, handle=b'i' * 32)


def test_challenge_row_round_trip(alice):
    row = WebAuthnChallenge.objects.create(
        id='abc', challenge=b'c' * 32, purpose=WebAuthnChallenge.REGISTER,
        user=alice, payload={'k': 'v'}, expires_at=timezone.now())
    row.refresh_from_db()
    assert bytes(row.challenge) == b'c' * 32
    assert row.payload == {'k': 'v'}
    assert {p for p, _label in WebAuthnChallenge.PURPOSES} == {
        'login', 'register', 'signup', 'recover'}


def test_deleting_user_cascades(alice):
    _passkey(alice)
    PasskeyUserHandle.objects.create(user=alice, handle=b'h' * 32)
    alice.delete()
    assert Passkey.objects.count() == 0
    assert PasskeyUserHandle.objects.count() == 0
```

- [ ] **Step 2: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_models.py -v --no-cov`
Expected: FAIL — `ImportError: cannot import name 'Passkey'`.

- [ ] **Step 3: Add the models**

Append to `app/user_data/models.py`:

```python


class Passkey(models.Model):
    """One WebAuthn credential; a user may register several."""
    user = models.ForeignKey(User, related_name='passkeys', on_delete=models.CASCADE)
    credential_id = models.CharField(max_length=1400, unique=True)  # base64url
    public_key = models.BinaryField()  # COSE-encoded
    sign_count = models.PositiveBigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    aaguid = models.CharField(max_length=36, blank=True)
    backed_up = models.BooleanField(default=False)
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)


class PasskeyUserHandle(models.Model):
    """Random WebAuthn user.id for an account (never the pk)."""
    user = models.OneToOneField(User, related_name='passkey_handle',
                                on_delete=models.CASCADE)
    handle = models.BinaryField(max_length=64, unique=True)


class WebAuthnChallenge(models.Model):
    """Single-use state for one begin/finish ceremony."""
    LOGIN = 'login'
    REGISTER = 'register'
    SIGNUP = 'signup'
    RECOVER = 'recover'
    PURPOSES = [(LOGIN, 'login'), (REGISTER, 'register'),
                (SIGNUP, 'signup'), (RECOVER, 'recover')]

    id = models.CharField(primary_key=True, max_length=64)
    challenge = models.BinaryField()
    purpose = models.CharField(max_length=16, choices=PURPOSES)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE)
    payload = models.JSONField(default=dict, blank=True)
    expires_at = models.DateTimeField(db_index=True)
```

- [ ] **Step 4: Generate and apply the migration**

Run:
```bash
docker compose exec -T web python manage.py makemigrations user_data --name passkeys
docker compose exec -T web python manage.py migrate
```
Expected: `user_data/migrations/0005_passkeys.py` created with `CreateModel` for `Passkey`, `PasskeyUserHandle`, `WebAuthnChallenge`; migrate prints `Applying user_data.0005_passkeys... OK`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_models.py -v --no-cov`
Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/models.py app/user_data/migrations/0005_passkeys.py app/user_data/tests/test_passkey_models.py
git commit -m "$(cat <<'EOF'
feat(passkey): add Passkey, PasskeyUserHandle and WebAuthnChallenge models

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Software authenticator and test fixtures

**Files:**
- Create: `app/user_data/tests/soft_authenticator.py`
- Modify: `app/user_data/tests/conftest.py`
- Test: `app/user_data/tests/test_soft_authenticator.py`

This helper was prototyped against py_webauthn 3.0.0 during planning: registrations and assertions verify; UV-off, wrong origin, wrong RP ID, corrupt signature, counter regression and wrong challenge are all rejected.

- [ ] **Step 1: Write the failing test**

Create `app/user_data/tests/test_soft_authenticator.py`:

```python
import pytest
from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers.exceptions import InvalidAuthenticationResponse

from .soft_authenticator import SoftAuthenticator, b64url

CHALLENGE = b'c' * 32
RP = 'data.etipitaka.com'
ORIGIN = 'https://data.etipitaka.com'
REG_OPTIONS = {'rp': {'id': RP, 'name': 'E-Tipitaka'},
               'user': {'id': b64url(b'h' * 32), 'name': 'alice', 'displayName': 'alice'},
               'challenge': b64url(CHALLENGE)}
AUTH_OPTIONS = {'rpId': RP, 'challenge': b64url(CHALLENGE)}


def _register(authenticator):
    return verify_registration_response(
        credential=authenticator.register(REG_OPTIONS), expected_challenge=CHALLENGE,
        expected_rp_id=RP, expected_origin=ORIGIN, require_user_verification=True)


def _authenticate(authenticator, verified, **tamper):
    return verify_authentication_response(
        credential=authenticator.assert_(AUTH_OPTIONS, **tamper),
        expected_challenge=CHALLENGE, expected_rp_id=RP, expected_origin=ORIGIN,
        credential_public_key=verified.credential_public_key,
        credential_current_sign_count=0, require_user_verification=True)


def test_registration_verifies():
    authenticator = SoftAuthenticator()
    verified = _register(authenticator)
    assert verified.user_verified is True
    assert verified.credential_backed_up is True
    assert authenticator.user_handle == b'h' * 32


def test_assertion_verifies_and_counts():
    authenticator = SoftAuthenticator()
    verified = _register(authenticator)
    assert _authenticate(authenticator, verified).new_sign_count == 1


def test_corrupt_signature_is_rejected():
    authenticator = SoftAuthenticator()
    verified = _register(authenticator)
    with pytest.raises(InvalidAuthenticationResponse):
        _authenticate(authenticator, verified, corrupt_signature=True)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_soft_authenticator.py -v --no-cov`
Expected: FAIL — `ModuleNotFoundError: No module named 'user_data.tests.soft_authenticator'`.

- [ ] **Step 3: Write the software authenticator**

Create `app/user_data/tests/soft_authenticator.py`:

```python
"""Software WebAuthn authenticator for tests.

Produces real `none`-attestation registration responses and ES256-signed
assertions in the WebAuthn JSON shape that browsers, iOS and Android send, so
tests exercise py_webauthn's actual verification instead of mocking it. Each
call takes keyword knobs that tamper with exactly one property.
"""
import base64
import hashlib
import json
import secrets
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40

DEFAULT_ORIGIN = 'https://data.etipitaka.com'


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64url(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


class SoftAuthenticator:
    """One authenticator holding one credential (like one passkey)."""

    def __init__(self, aaguid=b'\x00' * 16):
        self.aaguid = aaguid
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.user_handle = None
        self.sign_count = 0

    def _cose_public_key(self):
        numbers = self.private_key.public_key().public_numbers()
        return cbor2.dumps({
            1: 2,    # kty: EC2
            3: -7,   # alg: ES256
            -1: 1,   # crv: P-256
            -2: numbers.x.to_bytes(32, 'big'),
            -3: numbers.y.to_bytes(32, 'big'),
        })

    @staticmethod
    def _client_data(kind, challenge_b64, origin):
        return json.dumps({'type': kind, 'challenge': challenge_b64,
                           'origin': origin, 'crossOrigin': False}).encode()

    @staticmethod
    def _flags(uv, backed_up, extra=0):
        flags = FLAG_UP | extra
        if uv:
            flags |= FLAG_UV
        if backed_up:
            flags |= FLAG_BE | FLAG_BS
        return flags

    def register(self, options, origin=DEFAULT_ORIGIN, rp_id=None, uv=True,
                 backed_up=True):
        """Answer PublicKeyCredentialCreationOptionsJSON (a dict)."""
        rp_id = rp_id or options['rp']['id']
        self.user_handle = unb64url(options['user']['id'])
        client_data = self._client_data('webauthn.create', options['challenge'], origin)
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self._flags(uv, backed_up, FLAG_AT)])
            + struct.pack('>I', self.sign_count)
            + self.aaguid
            + struct.pack('>H', len(self.credential_id))
            + self.credential_id
            + self._cose_public_key()
        )
        attestation = cbor2.dumps({'fmt': 'none', 'attStmt': {}, 'authData': auth_data})
        return {
            'id': b64url(self.credential_id),
            'rawId': b64url(self.credential_id),
            'type': 'public-key',
            'response': {
                'clientDataJSON': b64url(client_data),
                'attestationObject': b64url(attestation),
                'transports': ['internal', 'hybrid'],
            },
            'clientExtensionResults': {},
            'authenticatorAttachment': 'platform',
        }

    def assert_(self, options, origin=DEFAULT_ORIGIN, rp_id=None, uv=True,
                backed_up=True, user_handle=None, omit_user_handle=False,
                sign_count=None, corrupt_signature=False):
        """Answer PublicKeyCredentialRequestOptionsJSON (a dict).

        The counter goes up by one unless `sign_count` pins it; pinning 0 on
        every call models a synced passkey, which never counts.
        """
        rp_id = rp_id or options['rpId']
        if sign_count is None:
            self.sign_count += 1
            sign_count = self.sign_count
        client_data = self._client_data('webauthn.get', options['challenge'], origin)
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self._flags(uv, backed_up)])
            + struct.pack('>I', sign_count)
        )
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        if corrupt_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
        response = {
            'clientDataJSON': b64url(client_data),
            'authenticatorData': b64url(auth_data),
            'signature': b64url(signature),
        }
        if not omit_user_handle:
            response['userHandle'] = b64url(user_handle or self.user_handle)
        return {
            'id': b64url(self.credential_id),
            'rawId': b64url(self.credential_id),
            'type': 'public-key',
            'response': response,
            'clientExtensionResults': {},
            'authenticatorAttachment': 'platform',
        }
```

- [ ] **Step 4: Add shared fixtures to conftest**

In `app/user_data/tests/conftest.py`, add after the existing imports:

```python
from user_data.tests.soft_authenticator import SoftAuthenticator
```

Append to the end of the file:

```python


@pytest.fixture(autouse=True)
def _passkey_settings(settings):
    """Pin the relying party so a dev PASSKEY_* override never leaks into tests."""
    settings.PASSKEY_RP_ID = 'data.etipitaka.com'
    settings.PASSKEY_WEB_ORIGIN = 'https://data.etipitaka.com'
    settings.PASSKEY_ANDROID_PACKAGE = ''
    settings.PASSKEY_ANDROID_CERT_SHA256 = []


@pytest.fixture
def authenticator():
    return SoftAuthenticator()
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_soft_authenticator.py user_data/tests/test_passkey_config.py -v --no-cov`
Expected: 12 passed (the config tests still pass because they set the settings they read).

- [ ] **Step 6: Commit**

```bash
git add app/user_data/tests/soft_authenticator.py app/user_data/tests/test_soft_authenticator.py app/user_data/tests/conftest.py
git commit -m "$(cat <<'EOF'
test(passkey): software WebAuthn authenticator and fixtures

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Single-use challenge store

**Files:**
- Create: `app/user_data/passkey_challenges.py`
- Test: `app/user_data/tests/test_passkey_challenges.py`

- [ ] **Step 1: Write the failing test**

Create `app/user_data/tests/test_passkey_challenges.py`:

```python
from datetime import timedelta

import pytest
from django.utils import timezone

from user_data import passkey_challenges as challenges
from user_data.models import WebAuthnChallenge

pytestmark = pytest.mark.django_db


def _expire(row):
    WebAuthnChallenge.objects.filter(pk=row.id).update(
        expires_at=timezone.now() - timedelta(seconds=1))


def test_create_issues_random_challenge_with_ttl(alice, settings):
    settings.PASSKEY_CHALLENGE_TTL = 300
    before = timezone.now()
    row = challenges.create(WebAuthnChallenge.REGISTER, user=alice, payload={'a': 1})
    assert isinstance(row.challenge, bytes) and len(row.challenge) == 32
    assert len(row.id) >= 40
    assert (row.purpose, row.user, row.payload) == ('register', alice, {'a': 1})
    assert before + timedelta(seconds=299) < row.expires_at
    assert row.expires_at <= timezone.now() + timedelta(seconds=300)


def test_consume_returns_row_once():
    row = challenges.create(WebAuthnChallenge.LOGIN)
    got = challenges.consume(row.id, WebAuthnChallenge.LOGIN)
    assert got.challenge == row.challenge
    assert isinstance(got.challenge, bytes)
    with pytest.raises(challenges.ChallengeError):
        challenges.consume(row.id, WebAuthnChallenge.LOGIN)


def test_consume_rejects_expired():
    row = challenges.create(WebAuthnChallenge.LOGIN)
    _expire(row)
    with pytest.raises(challenges.ChallengeError):
        challenges.consume(row.id, WebAuthnChallenge.LOGIN)


def test_consume_rejects_wrong_purpose():
    row = challenges.create(WebAuthnChallenge.LOGIN)
    with pytest.raises(challenges.ChallengeError):
        challenges.consume(row.id, WebAuthnChallenge.REGISTER)


def test_consume_rejects_other_user_and_burns_row(alice, bob):
    row = challenges.create(WebAuthnChallenge.REGISTER, user=alice)
    with pytest.raises(challenges.ChallengeError):
        challenges.consume(row.id, WebAuthnChallenge.REGISTER, user=bob)
    assert not WebAuthnChallenge.objects.filter(pk=row.id).exists()


@pytest.mark.parametrize('bad', [None, '', 123, ['x']])
def test_consume_rejects_non_string_ids(bad):
    with pytest.raises(challenges.ChallengeError):
        challenges.consume(bad, WebAuthnChallenge.LOGIN)


def test_create_purges_expired_rows():
    old = challenges.create(WebAuthnChallenge.LOGIN)
    _expire(old)
    challenges.create(WebAuthnChallenge.LOGIN)
    assert not WebAuthnChallenge.objects.filter(pk=old.id).exists()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_challenges.py -v --no-cov`
Expected: FAIL — `ImportError: cannot import name 'passkey_challenges'`.

- [ ] **Step 3: Write the challenge store**

Create `app/user_data/passkey_challenges.py`:

```python
"""Single-use WebAuthn ceremony challenges, stored in the database.

No cache is shared across the gunicorn workers and native clients carry no
session cookie, so the state between a ceremony's begin and finish calls
lives in WebAuthnChallenge rows.
"""
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import WebAuthnChallenge


class ChallengeError(Exception):
    """Unknown, expired, reused, wrong-purpose or wrong-user challenge."""


def create(purpose, user=None, payload=None):
    now = timezone.now()
    WebAuthnChallenge.objects.filter(expires_at__lte=now).delete()
    return WebAuthnChallenge.objects.create(
        id=secrets.token_urlsafe(32), challenge=secrets.token_bytes(32),
        purpose=purpose, user=user, payload=payload or {},
        expires_at=now + timedelta(seconds=settings.PASSKEY_CHALLENGE_TTL))


def consume(challenge_id, purpose, user=None):
    """Delete and return the challenge, or raise ChallengeError.

    The row is gone before the caller verifies anything, so a failed
    verification burns it too and a concurrent replay finds nothing. Call
    this outside any enclosing transaction.atomic(): a rollback there would
    resurrect the row.
    """
    if not isinstance(challenge_id, str) or not challenge_id:
        raise ChallengeError()
    with transaction.atomic():
        row = (WebAuthnChallenge.objects.select_for_update()
               .filter(pk=challenge_id, purpose=purpose, expires_at__gt=timezone.now())
               .first())
        if row is None:
            raise ChallengeError()
        row.delete()
    if user is not None and row.user_id != user.pk:
        raise ChallengeError()
    row.challenge = bytes(row.challenge)
    return row
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_challenges.py -v --no-cov`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add app/user_data/passkey_challenges.py app/user_data/tests/test_passkey_challenges.py
git commit -m "$(cat <<'EOF'
feat(passkey): single-use database challenge store

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Shared account identity serializer with username validation

**Files:**
- Modify: `app/user_data/serializers.py:9-23`
- Test: `app/user_data/tests/test_serializers.py`

- [ ] **Step 1: Write the failing tests**

Append to `app/user_data/tests/test_serializers.py` (the file already has `pytestmark = pytest.mark.django_db`):

```python


from user_data.serializers import AccountIdentitySerializer


@pytest.mark.parametrize('username', ['bad name', 'semi;colon', 'x' * 151])
def test_identity_rejects_invalid_usernames(username):
    s = AccountIdentitySerializer(data={'email': 'n@example.com', 'username': username})
    assert not s.is_valid()
    assert 'username' in s.errors


def test_identity_accepts_valid_new_user():
    s = AccountIdentitySerializer(data={'email': 'n@example.com', 'username': 'new.user+1'})
    assert s.is_valid(), s.errors


def test_identity_rejects_taken_username_and_email():
    User.objects.create_user('alice', 'alice@example.com', 'pw12345678')
    s = AccountIdentitySerializer(data={'email': 'alice@example.com', 'username': 'alice'})
    assert not s.is_valid()
    assert set(s.errors) == {'username', 'email'}


def test_register_serializer_rejects_invalid_username():
    s = RegisterSerializer(data={'email': 'n@example.com', 'username': 'bad name',
                                 'password1': 'pw12345678', 'password2': 'pw12345678'})
    assert not s.is_valid()
    assert 'username' in s.errors
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_serializers.py -v --no-cov`
Expected: FAIL — `ImportError: cannot import name 'AccountIdentitySerializer'`.

- [ ] **Step 3: Extract the identity serializer**

In `app/user_data/serializers.py`, add the import:

```python
from django.contrib.auth.validators import UnicodeUsernameValidator
```

Replace the start of `RegisterSerializer` (the class line, the `email`/`username` fields and the two `validate_*` methods) with:

```python
class AccountIdentitySerializer(serializers.Serializer):
    """Username + email rules shared by password signup and passkey signup."""
    email = serializers.EmailField()
    username = serializers.CharField(max_length=150,
                                     validators=[UnicodeUsernameValidator()])

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError(_("A user with that username already exists."))
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(_("A user with that email already exists."))
        return value


class RegisterSerializer(AccountIdentitySerializer):
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
```

Keep `RegisterSerializer.validate` and `create` exactly as they are.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_serializers.py user_data/tests/test_auth.py -v --no-cov`
Expected: all passed (existing registration tests use valid usernames).

- [ ] **Step 5: Commit**

```bash
git add app/user_data/serializers.py app/user_data/tests/test_serializers.py
git commit -m "$(cat <<'EOF'
feat(auth): shared account identity serializer with username validator

Registration now rejects usernames Django's own model validator would
reject; passkey signup reuses the same rules.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Registration ceremony (link a passkey to an account)

**Files:**
- Create: `app/user_data/passkey_service.py`
- Create: `app/templates/email/passkey_added.txt`
- Test: `app/user_data/tests/test_passkey_service.py`

- [ ] **Step 1: Write the failing tests**

Create `app/user_data/tests/test_passkey_service.py`:

```python
import pytest
from django.core import mail

from user_data import passkey_service as service
from user_data.models import Passkey, PasskeyUserHandle, WebAuthnChallenge
from user_data.passkey_config import android_origin

from .soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.django_db

APPLE_AAGUID = bytes.fromhex('fbfc3007154e4ecc8c0b6e020557d7bd')


def _register(user, authenticator, name=None, **tamper):
    challenge_id, options = service.begin_register(user)
    return service.finish_register(user, challenge_id,
                                   authenticator.register(options, **tamper), name=name)


# --- registration -----------------------------------------------------------

def test_begin_register_options(alice):
    challenge_id, options = service.begin_register(alice)
    assert options['rp'] == {'id': 'data.etipitaka.com', 'name': 'E-Tipitaka'}
    assert options['user']['name'] == 'alice'
    assert options['authenticatorSelection']['residentKey'] == 'required'
    assert options['authenticatorSelection']['userVerification'] == 'required'
    assert options['attestation'] == 'none'
    assert options['timeout'] == 300000
    assert options['excludeCredentials'] == []
    assert WebAuthnChallenge.objects.get(pk=challenge_id).purpose == 'register'


def test_user_handle_is_random_and_stable(alice):
    _id1, first = service.begin_register(alice)
    _id2, second = service.begin_register(alice)
    assert first['user']['id'] == second['user']['id']
    assert len(bytes(PasskeyUserHandle.objects.get(user=alice).handle)) == 32


def test_finish_register_stores_passkey_and_emails(alice, authenticator):
    passkey = _register(alice, authenticator, name='  My phone  ')
    assert passkey.user == alice
    assert passkey.name == 'My phone'
    assert passkey.backed_up is True
    assert passkey.transports == ['internal', 'hybrid']
    assert passkey.sign_count == 0
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ['alice@example.com']
    assert 'My phone' in mail.outbox[0].body
    assert 'https://data.etipitaka.com/account/security/' in mail.outbox[0].body


def test_default_name_comes_from_aaguid(alice):
    assert _register(alice, SoftAuthenticator(aaguid=APPLE_AAGUID)).name == 'Apple Passwords'


def test_default_name_falls_back_to_passkey(alice, authenticator):
    assert _register(alice, authenticator).name == 'Passkey'


def test_exclude_credentials_lists_existing_passkeys(alice, authenticator):
    passkey = _register(alice, authenticator)
    _challenge_id, options = service.begin_register(alice)
    assert [c['id'] for c in options['excludeCredentials']] == [passkey.credential_id]
    assert options['excludeCredentials'][0]['transports'] == ['internal', 'hybrid']


@pytest.mark.parametrize('tamper', [
    {'uv': False}, {'origin': 'https://evil.example'}, {'rp_id': 'evil.example'}])
def test_finish_register_rejects_tampered_response(alice, authenticator, tamper):
    with pytest.raises(service.RegistrationFailed):
        _register(alice, authenticator, **tamper)
    assert not Passkey.objects.exists()


def test_finish_register_rejects_reused_challenge(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    service.finish_register(alice, challenge_id, authenticator.register(options))
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, SoftAuthenticator().register(options))


def test_finish_register_rejects_challenge_of_other_user(alice, bob, authenticator):
    challenge_id, options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(bob, challenge_id, authenticator.register(options))


def test_finish_register_rejects_duplicate_credential(alice, bob, authenticator):
    _register(alice, authenticator)
    with pytest.raises(service.RegistrationFailed):
        _register(bob, authenticator)


@pytest.mark.parametrize('credential', [None, 'x', [], {}])
def test_finish_register_rejects_malformed_credential(alice, credential):
    challenge_id, _options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, credential)


def test_android_origin_accepted_when_configured(alice, authenticator, settings):
    fingerprint = ':'.join(['01'] * 32)
    settings.PASSKEY_ANDROID_CERT_SHA256 = [fingerprint]
    assert _register(alice, authenticator, origin=android_origin(fingerprint)).pk
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_service.py -v --no-cov`
Expected: FAIL — `ImportError: cannot import name 'passkey_service'`.

- [ ] **Step 3: Write the notification email template**

Create `app/templates/email/passkey_added.txt`:

```
{% load i18n %}{% autoescape off %}{% blocktrans %}Hello {{ username }},{% endblocktrans %}

{% blocktrans %}A new passkey named "{{ passkey_name }}" was added to your E-Tipitaka account.{% endblocktrans %}

{% trans "You can review your passkeys here:" %}
{{ security_url }}

{% trans "If this was not you, recover your account now and remove the passkey:" %}
{{ reset_url }}

-- E-Tipitaka
{% endautoescape %}
```

- [ ] **Step 4: Write the service module (registration part)**

Create `app/user_data/passkey_service.py`:

```python
"""Passkey ceremonies: registration, login, step-up, signup and recovery.

Plain functions over users and WebAuthn JSON dicts -- never a request -- so
the views stay thin and every rule is testable without HTTP. py_webauthn
performs the cryptographic checks (signature, RP ID hash, origin, UV flag,
sign counter); this module owns challenges, account rules and persistence.
See docs/superpowers/specs/2026-09-14-passkey-login-design.md.
"""
import json
import logging
import secrets

from django.conf import settings
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.template.loader import render_to_string
from django.utils.translation import gettext as _
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (AttestationConveyancePreference,
                                      AuthenticatorSelectionCriteria,
                                      AuthenticatorTransport,
                                      PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement,
                                      UserVerificationRequirement)

from . import passkey_challenges as challenges
from . import passkey_config as config
from .models import Passkey, PasskeyUserHandle, WebAuthnChallenge

log = logging.getLogger(__name__)

# Display names of common passkey providers, keyed by AAGUID
# (github.com/passkeydeveloper/passkey-authenticator-aaguids).
AAGUID_NAMES = {
    'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'Apple Passwords',
    'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (Managed)',
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
    '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
    '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
    'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
    'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
}
_TRANSPORTS = {t.value for t in AuthenticatorTransport}


class PasskeyError(Exception):
    """Base class for failures the views turn into 4xx responses."""


class RegistrationFailed(PasskeyError):
    """The challenge or the registration response did not verify."""


def clean_name(name):
    return name.strip()[:100] if isinstance(name, str) else ''


def _options_json(options):
    return json.loads(options_to_json(options))


def _consume(challenge_id, purpose, user, error):
    try:
        return challenges.consume(challenge_id, purpose, user=user)
    except challenges.ChallengeError as exc:
        raise error() from exc


def _handle_for(user):
    row, _created = PasskeyUserHandle.objects.get_or_create(
        user=user, defaults={'handle': secrets.token_bytes(32)})
    return bytes(row.handle)


def _descriptors(user):
    return [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(p.credential_id),
            transports=[AuthenticatorTransport(t) for t in p.transports if t in _TRANSPORTS])
        for p in user.passkeys.order_by('pk')
    ]


def _registration_options(challenge, username, handle, exclude):
    return _options_json(generate_registration_options(
        rp_id=config.rp_id(), rp_name=settings.PASSKEY_RP_NAME,
        user_name=username, user_id=handle, user_display_name=username,
        challenge=challenge, timeout=settings.PASSKEY_CHALLENGE_TTL * 1000,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=exclude))


def _verify_registration(challenge, credential):
    if not isinstance(credential, dict):
        raise RegistrationFailed()
    try:
        return verify_registration_response(
            credential=credential, expected_challenge=challenge,
            expected_rp_id=config.rp_id(), expected_origin=config.expected_origins(),
            require_user_verification=True)
    except WebAuthnException as exc:
        log.info('passkey registration rejected: %s', type(exc).__name__)
        raise RegistrationFailed() from exc


def _store_passkey(user, verified, credential, name):
    aaguid = str(verified.aaguid)
    transports = [t for t in (credential.get('response') or {}).get('transports') or []
                  if isinstance(t, str) and t in _TRANSPORTS]
    try:
        with transaction.atomic():
            return Passkey.objects.create(
                user=user, credential_id=bytes_to_base64url(verified.credential_id),
                public_key=verified.credential_public_key,
                sign_count=verified.sign_count, transports=transports, aaguid=aaguid,
                backed_up=verified.credential_backed_up,
                name=clean_name(name) or AAGUID_NAMES.get(aaguid, 'Passkey'))
    except IntegrityError as exc:  # credential already registered to some account
        raise RegistrationFailed() from exc


def _send_passkey_added_email(user, passkey):
    if not user.email:
        return
    body = render_to_string('email/passkey_added.txt', {
        'username': user.username, 'passkey_name': passkey.name,
        'security_url': config.web_origin() + '/account/security/',
        'reset_url': config.web_origin() + '/password_reset/'})
    send_mail(_('A passkey was added to your E-Tipitaka account'), body,
              settings.DEFAULT_FROM_EMAIL, [user.email])


def _begin_registration(user, purpose):
    row = challenges.create(purpose, user=user)
    return row.id, _registration_options(row.challenge, user.username,
                                         _handle_for(user), _descriptors(user))


def _finish_registration(user, purpose, challenge_id, credential, name):
    row = _consume(challenge_id, purpose, user, RegistrationFailed)
    verified = _verify_registration(row.challenge, credential)
    return _store_passkey(user, verified, credential, name)


def begin_register(user):
    """Options for adding a passkey to a signed-in account (after step-up)."""
    return _begin_registration(user, WebAuthnChallenge.REGISTER)


def finish_register(user, challenge_id, credential, name=None):
    passkey = _finish_registration(user, WebAuthnChallenge.REGISTER,
                                   challenge_id, credential, name)
    _send_passkey_added_email(user, passkey)
    return passkey
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_service.py -v --no-cov`
Expected: 17 passed.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/passkey_service.py app/templates/email/passkey_added.txt app/user_data/tests/test_passkey_service.py
git commit -m "$(cat <<'EOF'
feat(passkey): registration ceremony with added-passkey email

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---
### Task 7: Login ceremony and step-up

**Files:**
- Modify: `app/user_data/passkey_service.py`
- Modify: `app/user_data/tests/conftest.py`
- Test: `app/user_data/tests/test_passkey_service.py`

- [ ] **Step 1: Add test helpers to conftest**

Append to `app/user_data/tests/conftest.py`:

```python


def add_passkey(user, authenticator, name=None):
    """Register `authenticator` as a passkey of `user` through the real service."""
    from user_data import passkey_service
    challenge_id, options = passkey_service.begin_register(user)
    return passkey_service.finish_register(user, challenge_id,
                                           authenticator.register(options), name=name)


def login_assertion(authenticator, **tamper):
    """(challenge_id, credential) for a fresh login challenge."""
    from user_data import passkey_service
    challenge_id, options = passkey_service.begin_login()
    return challenge_id, authenticator.assert_(options, **tamper)
```

- [ ] **Step 2: Write the failing tests**

In `app/user_data/tests/test_passkey_service.py`, add to the imports:

```python
from .conftest import add_passkey, login_assertion
```

Append:

```python


# --- login ------------------------------------------------------------------

def test_begin_login_options():
    challenge_id, options = service.begin_login()
    assert options['rpId'] == 'data.etipitaka.com'
    assert options['allowCredentials'] == []
    assert options['userVerification'] == 'required'
    assert WebAuthnChallenge.objects.get(pk=challenge_id).purpose == 'login'


def test_finish_login_returns_user_and_records_use(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    assert service.finish_login(*login_assertion(authenticator)) == alice
    passkey.refresh_from_db()
    assert passkey.sign_count == 1
    assert passkey.last_used_at is not None
    alice.refresh_from_db()
    assert alice.last_login is not None


def test_synced_passkey_with_zero_counter_logs_in_repeatedly(alice, authenticator):
    add_passkey(alice, authenticator)
    for _i in range(2):
        assert service.finish_login(*login_assertion(authenticator, sign_count=0)) == alice


@pytest.mark.parametrize('tamper', [
    {'uv': False}, {'origin': 'https://evil.example'}, {'rp_id': 'evil.example'},
    {'corrupt_signature': True}, {'omit_user_handle': True}, {'user_handle': b'x' * 32}])
def test_finish_login_rejects_tampered_assertion(alice, authenticator, tamper):
    add_passkey(alice, authenticator)
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(*login_assertion(authenticator, **tamper))


def test_finish_login_rejects_counter_regression(alice, authenticator):
    add_passkey(alice, authenticator)
    service.finish_login(*login_assertion(authenticator, sign_count=5))
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(*login_assertion(authenticator, sign_count=3))


def test_finish_login_rejects_unknown_credential(alice, authenticator):
    add_passkey(alice, authenticator)
    stranger = SoftAuthenticator()
    stranger.user_handle = b'z' * 32
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(*login_assertion(stranger))


def test_finish_login_rejects_reused_challenge(alice, authenticator):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    service.finish_login(challenge_id, credential)
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


def test_register_challenge_cannot_finish_login(alice, authenticator):
    add_passkey(alice, authenticator)
    register_id, _register_options = service.begin_register(alice)
    _login_id, options = service.begin_login()
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(register_id, authenticator.assert_(options))


@pytest.mark.parametrize('credential', [None, 'x', [], {}])
def test_finish_login_rejects_malformed_credential(credential):
    challenge_id, _options = service.begin_login()
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


def test_finish_login_inactive_user(alice, authenticator):
    add_passkey(alice, authenticator)
    alice.is_active = False
    alice.save()
    with pytest.raises(service.InactiveUser):
        service.finish_login(*login_assertion(authenticator))


# --- step-up ----------------------------------------------------------------

def test_step_up_with_password(alice):
    service.verify_step_up(alice, password='alicepass123')
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, password='wrong')


def test_step_up_password_refused_for_passkey_only_user(alice):
    alice.set_unusable_password()
    alice.save()
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, password='alicepass123')


def test_step_up_with_own_passkey(alice, authenticator):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    service.verify_step_up(alice, assertion={'challenge_id': challenge_id,
                                             'credential': credential})


def test_step_up_rejects_other_users_passkey(alice, bob, authenticator):
    add_passkey(bob, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, assertion={'challenge_id': challenge_id,
                                                 'credential': credential})


@pytest.mark.parametrize('assertion', [None, 'x', {}, {'challenge_id': 'nope', 'credential': {}}])
def test_step_up_rejects_missing_or_bad_assertion(alice, assertion):
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, assertion=assertion)
```

- [ ] **Step 3: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_service.py -v --no-cov`
Expected: FAIL — `AttributeError: module 'user_data.passkey_service' has no attribute 'begin_login'`.

- [ ] **Step 4: Implement login and step-up**

In `app/user_data/passkey_service.py`:

Replace the imports block from `import json` down to `from .models import ...` with:

```python
import hmac
import json
import logging
import secrets

from django.conf import settings
from django.contrib.auth.models import update_last_login
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.translation import gettext as _
from webauthn import (generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers import (base64url_to_bytes, bytes_to_base64url,
                              parse_authentication_credential_json)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (AttestationConveyancePreference,
                                      AuthenticatorSelectionCriteria,
                                      AuthenticatorTransport,
                                      PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement,
                                      UserVerificationRequirement)

from . import passkey_challenges as challenges
from . import passkey_config as config
from .models import Passkey, PasskeyUserHandle, WebAuthnChallenge
```

After `class RegistrationFailed`, add:

```python


class InvalidCredentials(PasskeyError):
    """The challenge or the assertion did not verify (deliberately generic)."""


class InactiveUser(PasskeyError):
    """The assertion verified but the account's email is not verified yet."""


class StepUpFailed(PasskeyError):
    """Neither a password nor a passkey assertion proved the account holder."""
```

Append to the end of the module:

```python


def begin_login():
    """Options for a username-less login: the authenticator picks the account."""
    row = challenges.create(WebAuthnChallenge.LOGIN)
    return row.id, _options_json(generate_authentication_options(
        rp_id=config.rp_id(), challenge=row.challenge,
        timeout=settings.PASSKEY_CHALLENGE_TTL * 1000,
        user_verification=UserVerificationRequirement.REQUIRED))


def _verify_assertion(challenge_id, credential):
    """Verify a login assertion and return its Passkey with usage recorded."""
    row = _consume(challenge_id, WebAuthnChallenge.LOGIN, None, InvalidCredentials)
    if not isinstance(credential, dict):
        raise InvalidCredentials()
    try:
        parsed = parse_authentication_credential_json(credential)
    except WebAuthnException as exc:
        raise InvalidCredentials() from exc
    passkey = None
    if parsed.raw_id:
        passkey = (Passkey.objects.select_related('user')
                   .filter(credential_id=bytes_to_base64url(parsed.raw_id)).first())
    if passkey is None:
        raise InvalidCredentials()
    handle = (PasskeyUserHandle.objects.filter(user_id=passkey.user_id)
              .values_list('handle', flat=True).first())
    claimed = parsed.response.user_handle
    if handle is None or claimed is None or not hmac.compare_digest(bytes(handle), claimed):
        raise InvalidCredentials()
    try:
        verified = verify_authentication_response(
            credential=parsed, expected_challenge=row.challenge,
            expected_rp_id=config.rp_id(), expected_origin=config.expected_origins(),
            credential_public_key=bytes(passkey.public_key),
            credential_current_sign_count=passkey.sign_count,
            require_user_verification=True)
    except WebAuthnException as exc:
        # Includes a non-increasing sign counter: possibly a cloned authenticator.
        log.warning('passkey assertion rejected for passkey %s: %s',
                    passkey.pk, type(exc).__name__)
        raise InvalidCredentials() from exc
    passkey.sign_count = verified.new_sign_count
    passkey.backed_up = verified.credential_backed_up
    passkey.last_used_at = timezone.now()
    passkey.save(update_fields=['sign_count', 'backed_up', 'last_used_at'])
    return passkey


def finish_login(challenge_id, credential):
    """Return the active user the assertion proves."""
    user = _verify_assertion(challenge_id, credential).user
    if not user.is_active:
        raise InactiveUser()
    update_last_login(None, user)
    return user


def verify_step_up(user, password=None, assertion=None):
    """Raise StepUpFailed unless the caller re-proved they hold `user`.

    Proof is the current password, or a fresh assertion (a begin_login
    challenge_id plus credential) made with one of `user`'s own passkeys.
    """
    if password is not None:
        if (isinstance(password, str) and user.has_usable_password()
                and user.check_password(password)):
            return
        raise StepUpFailed()
    if isinstance(assertion, dict):
        try:
            passkey = _verify_assertion(assertion.get('challenge_id'),
                                        assertion.get('credential'))
        except InvalidCredentials as exc:
            raise StepUpFailed() from exc
        if passkey.user_id == user.pk:
            return
    raise StepUpFailed()
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_service.py -v --no-cov`
Expected: 43 passed.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/passkey_service.py app/user_data/tests/conftest.py app/user_data/tests/test_passkey_service.py
git commit -m "$(cat <<'EOF'
feat(passkey): username-less login ceremony and step-up verification

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Signup ceremony

**Files:**
- Modify: `app/user_data/passkey_service.py`
- Test: `app/user_data/tests/test_passkey_service.py`

- [ ] **Step 1: Write the failing tests**

In `app/user_data/tests/test_passkey_service.py`, add to the imports:

```python
from django.contrib.auth.models import User
```

Append:

```python


# --- signup -----------------------------------------------------------------

def _signup(authenticator, username='newbie', email='n@example.com', **tamper):
    challenge_id, options = service.begin_signup(username, email)
    return service.finish_signup(challenge_id, authenticator.register(options, **tamper),
                                 name='Phone')


def test_begin_signup_creates_no_user():
    challenge_id, options = service.begin_signup('newbie', 'n@example.com')
    assert options['user']['name'] == 'newbie'
    assert not User.objects.filter(username='newbie').exists()
    assert WebAuthnChallenge.objects.get(pk=challenge_id).payload['email'] == 'n@example.com'


def test_begin_signup_rejects_invalid_identity(alice):
    with pytest.raises(service.SignupInvalid) as exc:
        service.begin_signup('alice', 'not-an-email')
    assert set(exc.value.errors) == {'username', 'email'}
    assert all(isinstance(m, str) for msgs in exc.value.errors.values() for m in msgs)


def test_finish_signup_creates_inactive_passkey_only_user(authenticator):
    user = _signup(authenticator)
    assert user.is_active is False
    assert user.has_usable_password() is False
    assert user.email == 'n@example.com'
    assert user.passkeys.get().name == 'Phone'
    assert bytes(PasskeyUserHandle.objects.get(user=user).handle) == authenticator.user_handle
    assert mail.outbox == []  # the view sends the verification email


def test_signup_user_can_log_in_after_activation(authenticator):
    user = _signup(authenticator)
    with pytest.raises(service.InactiveUser):
        service.finish_login(*login_assertion(authenticator))
    user.is_active = True
    user.save()
    assert service.finish_login(*login_assertion(authenticator)) == user


def test_finish_signup_rejects_username_taken_since_begin(authenticator):
    challenge_id, options = service.begin_signup('newbie', 'n@example.com')
    User.objects.create_user('newbie', 'other@example.com', 'pw12345678')
    with pytest.raises(service.SignupInvalid) as exc:
        service.finish_signup(challenge_id, authenticator.register(options))
    assert 'username' in exc.value.errors
    assert Passkey.objects.count() == 0


def test_finish_signup_integrity_race_reports_username(authenticator, monkeypatch):
    challenge_id, options = service.begin_signup('newbie', 'n@example.com')
    User.objects.create_user('newbie', 'other@example.com', 'pw12345678')

    class AlwaysValid:
        errors = {}

        def __init__(self, data):
            pass

        def is_valid(self):
            return True

    monkeypatch.setattr(service, 'AccountIdentitySerializer', AlwaysValid)
    with pytest.raises(service.SignupInvalid) as exc:
        service.finish_signup(challenge_id, authenticator.register(options))
    assert 'username' in exc.value.errors


def test_finish_signup_rejects_bad_response(authenticator):
    with pytest.raises(service.RegistrationFailed):
        _signup(authenticator, uv=False)
    assert not User.objects.filter(username='newbie').exists()


def test_finish_signup_duplicate_credential_rolls_back_user(alice, authenticator):
    add_passkey(alice, authenticator)
    with pytest.raises(service.RegistrationFailed):
        _signup(authenticator)
    assert not User.objects.filter(username='newbie').exists()
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_service.py -v --no-cov -k signup`
Expected: FAIL — `AttributeError: module 'user_data.passkey_service' has no attribute 'begin_signup'`.

- [ ] **Step 3: Implement signup**

In `app/user_data/passkey_service.py`:

Add to the imports:

```python
from django.contrib.auth.models import User, update_last_login
```
(replacing the existing `from django.contrib.auth.models import update_last_login` line) and

```python
from .serializers import AccountIdentitySerializer
```

After `class StepUpFailed`, add:

```python


class SignupInvalid(PasskeyError):
    """Username/email invalid or taken; `errors` maps field -> messages."""

    def __init__(self, errors):
        super().__init__(errors)
        self.errors = errors
```

Append to the end of the module:

```python


def _plain_errors(errors):
    return {field: [str(message) for message in messages]
            for field, messages in errors.items()}


def begin_signup(username, email):
    """Validate a new account's identity and return registration options.

    No User row exists until finish_signup verifies the passkey.
    """
    serializer = AccountIdentitySerializer(data={'username': username, 'email': email})
    if not serializer.is_valid():
        raise SignupInvalid(_plain_errors(serializer.errors))
    data = serializer.validated_data
    handle = secrets.token_bytes(32)
    row = challenges.create(WebAuthnChallenge.SIGNUP, payload={
        'username': data['username'], 'email': data['email'],
        'handle': bytes_to_base64url(handle)})
    return row.id, _registration_options(row.challenge, data['username'], handle, [])


def finish_signup(challenge_id, credential, name=None):
    """Create the inactive, passwordless account with its first passkey.

    The caller sends the verification email.
    """
    row = _consume(challenge_id, WebAuthnChallenge.SIGNUP, None, RegistrationFailed)
    verified = _verify_registration(row.challenge, credential)
    payload = row.payload
    serializer = AccountIdentitySerializer(data={'username': payload['username'],
                                                 'email': payload['email']})
    if not serializer.is_valid():  # taken since begin_signup
        raise SignupInvalid(_plain_errors(serializer.errors))
    try:
        with transaction.atomic():
            user = User(username=payload['username'], email=payload['email'],
                        is_active=False)
            user.set_unusable_password()
            user.save()
            PasskeyUserHandle.objects.create(user=user,
                                             handle=base64url_to_bytes(payload['handle']))
            _store_passkey(user, verified, credential, name)
    except IntegrityError as exc:  # username taken between the check and the insert
        raise SignupInvalid({'username': [_('A user with that username already exists.')]}) from exc
    return user
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_service.py -v --no-cov`
Expected: 51 passed.

- [ ] **Step 5: Commit**

```bash
git add app/user_data/passkey_service.py app/user_data/tests/test_passkey_service.py
git commit -m "$(cat <<'EOF'
feat(passkey): passkey signup creates inactive passwordless account

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Token revocation and recovery ceremony

**Files:**
- Create: `app/user_data/account_tokens.py`
- Modify: `app/user_data/passkey_service.py`
- Test: `app/user_data/tests/test_account_tokens.py`, `app/user_data/tests/test_passkey_service.py`

- [ ] **Step 1: Write the failing tests**

Create `app/user_data/tests/test_account_tokens.py`:

```python
import pytest
from oauth2_provider.models import AccessToken, RefreshToken
from rest_framework.authtoken.models import Token

from user_data.account_tokens import revoke_all_tokens

from .conftest import make_oauth_token

pytestmark = pytest.mark.django_db


def test_revoke_all_tokens_removes_drf_and_oauth_tokens(alice, bob):
    access = make_oauth_token(alice)
    RefreshToken.objects.create(user=alice, application=access.application,
                                token='r-1', access_token=access)
    make_oauth_token(bob)
    revoke_all_tokens(alice)
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert not RefreshToken.objects.filter(user=alice).exists()
    assert Token.objects.filter(user=bob).exists()
    assert AccessToken.objects.filter(user=bob).exists()
```

In `app/user_data/tests/test_passkey_service.py`, add to the imports:

```python
from oauth2_provider.models import AccessToken
from rest_framework.authtoken.models import Token

from .conftest import make_oauth_token
```

Append:

```python


# --- recovery ---------------------------------------------------------------

def test_recover_adds_passkey_and_revokes_tokens(alice, authenticator):
    make_oauth_token(alice)
    challenge_id, options = service.begin_recover(alice)
    passkey = service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert passkey.user == alice
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert len(mail.outbox) == 1


def test_register_challenge_cannot_finish_recovery(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert Token.objects.filter(user=alice).exists()
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_account_tokens.py user_data/tests/test_passkey_service.py -v --no-cov -k "revoke or recover"`
Expected: FAIL — `ModuleNotFoundError: No module named 'user_data.account_tokens'`.

- [ ] **Step 3: Write the revocation module**

Create `app/user_data/account_tokens.py`:

```python
"""Revoke every API credential a user holds: the DRF token and OAuth tokens."""
from oauth2_provider.models import (get_access_token_model, get_grant_model,
                                    get_refresh_token_model)
from rest_framework.authtoken.models import Token


def revoke_all_tokens(user):
    Token.objects.filter(user=user).delete()
    get_refresh_token_model().objects.filter(user=user).delete()
    get_access_token_model().objects.filter(user=user).delete()
    get_grant_model().objects.filter(user=user).delete()
```

- [ ] **Step 4: Add the recovery ceremony**

In `app/user_data/passkey_service.py`, add to the imports:

```python
from .account_tokens import revoke_all_tokens
```

Append to the end of the module:

```python


def begin_recover(user):
    """Options for creating a passkey from a valid account-recovery session."""
    return _begin_registration(user, WebAuthnChallenge.RECOVER)


def finish_recover(user, challenge_id, credential, name=None):
    """Store the new passkey and sign every other device out."""
    passkey = _finish_registration(user, WebAuthnChallenge.RECOVER,
                                   challenge_id, credential, name)
    revoke_all_tokens(user)
    _send_passkey_added_email(user, passkey)
    return passkey
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_account_tokens.py user_data/tests/test_passkey_service.py -v --no-cov`
Expected: 54 passed.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/account_tokens.py app/user_data/passkey_service.py app/user_data/tests/test_account_tokens.py app/user_data/tests/test_passkey_service.py
git commit -m "$(cat <<'EOF'
feat(passkey): recovery ceremony revokes DRF and OAuth tokens

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Passkey management (list, rename, delete, remove password)

**Files:**
- Create: `app/user_data/passkey_manage.py`
- Test: `app/user_data/tests/test_passkey_manage.py`

- [ ] **Step 1: Write the failing tests**

Create `app/user_data/tests/test_passkey_manage.py`:

```python
import pytest

from user_data import passkey_manage as manage

from .conftest import add_passkey
from .soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.django_db


def _drop_password(user):
    user.set_unusable_password()
    user.save()


def test_list_passkeys(alice, authenticator):
    passkey = add_passkey(alice, authenticator, name='Phone')
    assert manage.list_passkeys(alice) == {
        'has_password': True,
        'passkeys': [{'id': passkey.pk, 'name': 'Phone', 'authenticator': '',
                      'backed_up': True, 'created_at': passkey.created_at.isoformat(),
                      'last_used_at': None}]}


def test_rename_passkey(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    assert manage.rename_passkey(alice, passkey.pk, '  Laptop ').name == 'Laptop'


@pytest.mark.parametrize('name', ['', '   ', None, 5])
def test_rename_rejects_blank_name(alice, authenticator, name):
    passkey = add_passkey(alice, authenticator)
    with pytest.raises(manage.InvalidName):
        manage.rename_passkey(alice, passkey.pk, name)


def test_other_users_passkey_is_not_found(alice, bob, authenticator):
    passkey = add_passkey(bob, authenticator)
    with pytest.raises(manage.NotFound):
        manage.rename_passkey(alice, passkey.pk, 'x')
    with pytest.raises(manage.NotFound):
        manage.delete_passkey(alice, passkey.pk)


def test_bad_id_is_not_found(alice):
    with pytest.raises(manage.NotFound):
        manage.delete_passkey(alice, 'abc')


def test_delete_last_passkey_allowed_with_password(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    manage.delete_passkey(alice, passkey.pk)
    assert not alice.passkeys.exists()


def test_delete_last_passkey_refused_without_password(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    _drop_password(alice)
    with pytest.raises(manage.LockoutGuard):
        manage.delete_passkey(alice, passkey.pk)
    add_passkey(alice, SoftAuthenticator())
    manage.delete_passkey(alice, passkey.pk)  # another passkey remains
    assert alice.passkeys.count() == 1


def test_remove_password(alice, authenticator):
    add_passkey(alice, authenticator)
    assert manage.remove_password(alice, 'alicepass123').has_usable_password() is False
    alice.refresh_from_db()
    assert alice.has_usable_password() is False


def test_remove_password_requires_passkey(alice):
    with pytest.raises(manage.LockoutGuard):
        manage.remove_password(alice, 'alicepass123')


@pytest.mark.parametrize('password', ['wrong', None])
def test_remove_password_requires_correct_password(alice, authenticator, password):
    add_passkey(alice, authenticator)
    with pytest.raises(manage.WrongPassword):
        manage.remove_password(alice, password)


def test_remove_password_twice_is_lockout_guard(alice, authenticator):
    add_passkey(alice, authenticator)
    manage.remove_password(alice, 'alicepass123')
    alice.refresh_from_db()
    with pytest.raises(manage.LockoutGuard):
        manage.remove_password(alice, 'alicepass123')
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_manage.py -v --no-cov`
Expected: FAIL — `ImportError: cannot import name 'passkey_manage'`.

- [ ] **Step 3: Write the management module**

Create `app/user_data/passkey_manage.py`:

```python
"""Passkey management on a signed-in account: list, rename, delete, drop password."""
from django.contrib.auth.models import User
from django.db import transaction

from .models import Passkey
from .passkey_service import AAGUID_NAMES, PasskeyError, clean_name


class NotFound(PasskeyError):
    """No passkey with that id belongs to the caller."""


class InvalidName(PasskeyError):
    """Rename with an empty or non-string name."""


class LockoutGuard(PasskeyError):
    """The change would leave the account with no way to sign in."""


class WrongPassword(PasskeyError):
    """The confirming password did not match."""


def passkey_to_dict(passkey):
    return {
        'id': passkey.pk,
        'name': passkey.name,
        'authenticator': AAGUID_NAMES.get(passkey.aaguid, ''),
        'backed_up': passkey.backed_up,
        'created_at': passkey.created_at.isoformat(),
        'last_used_at': passkey.last_used_at.isoformat() if passkey.last_used_at else None,
    }


def list_passkeys(user):
    return {'has_password': user.has_usable_password(),
            'passkeys': [passkey_to_dict(p) for p in user.passkeys.order_by('created_at', 'pk')]}


def _own(user, passkey_id):
    try:
        return Passkey.objects.get(pk=int(passkey_id), user=user)
    except (Passkey.DoesNotExist, TypeError, ValueError) as exc:
        raise NotFound() from exc


def rename_passkey(user, passkey_id, name):
    passkey = _own(user, passkey_id)
    cleaned = clean_name(name)
    if not cleaned:
        raise InvalidName()
    passkey.name = cleaned
    passkey.save(update_fields=['name'])
    return passkey


def delete_passkey(user, passkey_id):
    """Delete, unless it is the only passkey of an account without a password."""
    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user.pk)
        passkey = _own(locked, passkey_id)
        if not locked.has_usable_password() and locked.passkeys.count() == 1:
            raise LockoutGuard()
        passkey.delete()


def remove_password(user, password):
    """Make the password unusable; allowed only while a passkey exists."""
    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user.pk)
        if not locked.has_usable_password() or not locked.passkeys.exists():
            raise LockoutGuard()
        if not isinstance(password, str) or not locked.check_password(password):
            raise WrongPassword()
        locked.set_unusable_password()
        locked.save(update_fields=['password'])
    return locked
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_manage.py -v --no-cov`
Expected: 15 passed.

- [ ] **Step 5: Commit**

```bash
git add app/user_data/passkey_manage.py app/user_data/tests/test_passkey_manage.py
git commit -m "$(cat <<'EOF'
feat(passkey): manage passkeys with lockout guards

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: JSON API — login and signup endpoints

**Files:**
- Create: `app/user_data/passkey_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_passkey_views.py`

- [ ] **Step 1: Write the failing tests**

Create `app/user_data/tests/test_passkey_views.py`:

```python
import pytest
from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from django.utils import translation
from rest_framework.authtoken.models import Token

from user_data.passkey_views import PasskeyRateThrottle

from .conftest import add_passkey

pytestmark = pytest.mark.django_db


def _post(client, url, body=None):
    return client.post(url, body if body is not None else {}, format='json')


def _login(client, authenticator, **tamper):
    begin = _post(client, '/api/passkeys/login/begin/').json()
    return _post(client, '/api/passkeys/login/finish/', {
        'challenge_id': begin['challenge_id'],
        'credential': authenticator.assert_(begin['options'], **tamper)})


def _signup_begin(client, username='newbie', email='n@example.com'):
    return _post(client, '/api/passkeys/signup/begin/', {'username': username, 'email': email})


# --- login ------------------------------------------------------------------

def test_login_begin(api):
    resp = _post(api, '/api/passkeys/login/begin/')
    assert resp.status_code == 200
    assert resp.json()['challenge_id']
    assert resp.json()['options']['rpId'] == 'data.etipitaka.com'


def test_login_finish_returns_same_token_as_password_login(api, alice, authenticator):
    add_passkey(alice, authenticator)
    resp = _login(api, authenticator)
    assert resp.status_code == 200
    assert resp.json() == {'key': Token.objects.get(user=alice).key}


def test_login_finish_creates_token_when_missing(api, alice, authenticator):
    add_passkey(alice, authenticator)
    Token.objects.filter(user=alice).delete()
    assert _login(api, authenticator).json()['key'] == Token.objects.get(user=alice).key


def test_login_finish_bad_assertion_matches_password_login_error(api, alice, authenticator):
    add_passkey(alice, authenticator)
    resp = _login(api, authenticator, corrupt_signature=True)
    password = api.post('/rest-auth/login/', {'username': 'alice', 'password': 'wrong'})
    assert resp.status_code == 400
    assert resp.json() == password.json()


def test_login_finish_inactive_account(api, alice, authenticator):
    add_passkey(alice, authenticator)
    alice.is_active = False
    alice.save()
    resp = _login(api, authenticator)
    with translation.override('th'):
        expected = translation.gettext('This account is not active. Please verify your email.')
    assert resp.status_code == 400
    assert resp.json() == {'non_field_errors': [expected]}


def test_login_finish_non_object_body(api):
    assert _post(api, '/api/passkeys/login/finish/', [1, 2]).status_code == 400


# --- signup -----------------------------------------------------------------

def test_signup_flow_sends_verification_email(api, authenticator):
    begin = _signup_begin(api)
    assert begin.status_code == 200
    body = begin.json()
    resp = _post(api, '/api/passkeys/signup/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options']), 'name': 'Phone'})
    assert resp.status_code == 201
    assert User.objects.get(username='newbie').is_active is False
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ['n@example.com']


def test_signup_begin_field_errors(api, alice):
    resp = _signup_begin(api, username='alice', email='bad')
    assert resp.status_code == 400
    assert set(resp.json()) == {'username', 'email'}


def test_signup_finish_bad_response(api, authenticator):
    body = _signup_begin(api).json()
    resp = _post(api, '/api/passkeys/signup/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options'], uv=False)})
    assert resp.status_code == 400
    assert 'detail' in resp.json()


def test_signup_finish_username_taken_since_begin(api, authenticator):
    body = _signup_begin(api).json()
    User.objects.create_user('newbie', 'x@example.com', 'pw12345678')
    resp = _post(api, '/api/passkeys/signup/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options'])})
    assert resp.status_code == 400
    assert 'username' in resp.json()


# --- throttling -------------------------------------------------------------

def test_passkey_endpoints_are_throttled(api, monkeypatch):
    cache.clear()
    monkeypatch.setattr(PasskeyRateThrottle, 'rate', '2/min')
    codes = [_post(api, '/api/passkeys/login/begin/').status_code for _i in range(3)]
    cache.clear()
    assert codes == [200, 200, 429]
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_views.py -v --no-cov`
Expected: FAIL — `ImportError: cannot import name 'passkey_views'`.

- [ ] **Step 3: Write the anonymous views**

Create `app/user_data/passkey_views.py`:

```python
"""JSON API for passkeys, used by the native apps and the web pages' fetch calls.

Account endpoints accept DRF Token and Session authentication only -- never
OAuth bearer tokens -- so a read-scoped MCP connector cannot manage a
user's credentials.
"""
from django.utils.translation import gettext as _
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes, throttle_classes)
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

from . import passkey_service as service
from .auth_views import _send_verification_email


class PasskeyRateThrottle(UserRateThrottle):
    """Per user when signed in, per client IP otherwise (rate: settings 'passkey')."""
    scope = 'passkey'


def _data(request):
    return request.data if isinstance(request.data, dict) else {}


def _ceremony(challenge_id, options):
    return Response({'challenge_id': challenge_id, 'options': options})


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyRateThrottle])
def login_begin(request):
    return _ceremony(*service.begin_login())


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyRateThrottle])
def login_finish(request):
    data = _data(request)
    try:
        user = service.finish_login(data.get('challenge_id'), data.get('credential'))
    except service.InactiveUser:
        message = _('This account is not active. Please verify your email.')
    except service.InvalidCredentials:
        message = _('Unable to log in with provided credentials.')
    else:
        token, _created = Token.objects.get_or_create(user=user)
        return Response({'key': token.key})
    return Response({'non_field_errors': [message]}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyRateThrottle])
def signup_begin(request):
    data = _data(request)
    try:
        return _ceremony(*service.begin_signup(data.get('username'), data.get('email')))
    except service.SignupInvalid as exc:
        return Response(exc.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyRateThrottle])
def signup_finish(request):
    data = _data(request)
    try:
        user = service.finish_signup(data.get('challenge_id'), data.get('credential'),
                                     data.get('name'))
    except service.SignupInvalid as exc:
        return Response(exc.errors, status=status.HTTP_400_BAD_REQUEST)
    except service.RegistrationFailed:
        return Response({'detail': _('Passkey registration failed.')},
                        status=status.HTTP_400_BAD_REQUEST)
    _send_verification_email(request, user)
    return Response({'detail': _('Verification e-mail sent.')}, status=status.HTTP_201_CREATED)
```

- [ ] **Step 4: Route them**

In `app/etipitaka_auth/urls.py`, change the imports line

```python
from user_data import canon_views
```
to
```python
from user_data import canon_views
from user_data import passkey_views
```

and after the `path('api/canon/dictionary/', ...)` line add:

```python
    path('api/passkeys/login/begin/', passkey_views.login_begin),
    path('api/passkeys/login/finish/', passkey_views.login_finish),
    path('api/passkeys/signup/begin/', passkey_views.signup_begin),
    path('api/passkeys/signup/finish/', passkey_views.signup_finish),
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_views.py -v --no-cov`
Expected: 11 passed.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/passkey_views.py app/etipitaka_auth/urls.py app/user_data/tests/test_passkey_views.py
git commit -m "$(cat <<'EOF'
feat(passkey): JSON API for passkey login and signup

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: JSON API — account endpoints (link, list, rename, delete, remove password)

**Files:**
- Modify: `app/user_data/passkey_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_passkey_views.py`

- [ ] **Step 1: Write the failing tests**

In `app/user_data/tests/test_passkey_views.py`, add to the imports:

```python
from django.test import Client
from rest_framework.test import APIClient

from .soft_authenticator import SoftAuthenticator
```

Append:

```python


# --- account endpoints ------------------------------------------------------

def _register_via_api(client, authenticator, proof):
    begin = _post(client, '/api/passkeys/register/begin/', proof)
    assert begin.status_code == 200, begin.content
    body = begin.json()
    return _post(client, '/api/passkeys/register/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options']), 'name': 'Phone'})


def test_register_with_password_step_up(auth_alice, alice, authenticator):
    resp = _register_via_api(auth_alice, authenticator, {'password': 'alicepass123'})
    assert resp.status_code == 201
    assert resp.json()['name'] == 'Phone'
    assert alice.passkeys.count() == 1


@pytest.mark.parametrize('proof', [{}, {'password': 'wrong'}, {'step_up': 'x'}])
def test_register_rejects_missing_or_wrong_step_up(auth_alice, proof):
    assert _post(auth_alice, '/api/passkeys/register/begin/', proof).status_code == 400


def test_register_with_passkey_step_up(auth_alice, alice, authenticator):
    add_passkey(alice, authenticator)
    alice.set_unusable_password()
    alice.save()
    begin = _post(APIClient(), '/api/passkeys/login/begin/').json()
    step_up = {'challenge_id': begin['challenge_id'],
               'credential': authenticator.assert_(begin['options'])}
    resp = _register_via_api(auth_alice, SoftAuthenticator(), {'step_up': step_up})
    assert resp.status_code == 201
    assert alice.passkeys.count() == 2


def test_register_finish_bad_response(auth_alice, authenticator):
    body = _post(auth_alice, '/api/passkeys/register/begin/',
                 {'password': 'alicepass123'}).json()
    resp = _post(auth_alice, '/api/passkeys/register/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options'], uv=False)})
    assert resp.status_code == 400


ACCOUNT_ENDPOINTS = [
    ('get', '/api/passkeys/'), ('post', '/api/passkeys/register/begin/'),
    ('post', '/api/passkeys/register/finish/'), ('patch', '/api/passkeys/1/'),
    ('delete', '/api/passkeys/1/'), ('post', '/api/passkeys/password/remove/')]


@pytest.mark.parametrize('method,url', ACCOUNT_ENDPOINTS)
def test_account_endpoints_reject_anonymous(method, url):
    assert getattr(APIClient(), method)(url, {}, format='json').status_code == 401


@pytest.mark.parametrize('method,url', ACCOUNT_ENDPOINTS)
def test_account_endpoints_reject_oauth_bearer(oauth_alice, method, url):
    assert getattr(oauth_alice, method)(url, {}, format='json').status_code == 401


def test_session_auth_is_accepted(client, alice):
    client.force_login(alice)
    assert client.get('/api/passkeys/').status_code == 200


def test_session_post_requires_csrf(alice):
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(alice)
    resp = csrf_client.post('/api/passkeys/register/begin/', {'password': 'alicepass123'},
                            content_type='application/json')
    assert resp.status_code == 403


def test_list_rename_delete(auth_alice, alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    url = '/api/passkeys/%d/' % passkey.pk
    listing = auth_alice.get('/api/passkeys/').json()
    assert listing['has_password'] is True
    assert [p['id'] for p in listing['passkeys']] == [passkey.pk]
    renamed = auth_alice.patch(url, {'name': 'Laptop'}, format='json')
    assert renamed.status_code == 200 and renamed.json()['name'] == 'Laptop'
    assert auth_alice.patch(url, {'name': ' '}, format='json').status_code == 400
    assert auth_alice.delete(url).status_code == 204
    assert auth_alice.delete(url).status_code == 404


def test_other_users_passkey_is_404(auth_alice, bob, authenticator):
    passkey = add_passkey(bob, authenticator)
    assert auth_alice.delete('/api/passkeys/%d/' % passkey.pk).status_code == 404


def test_remove_password_then_last_passkey_is_guarded(auth_alice, alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    remove = '/api/passkeys/password/remove/'
    assert _post(auth_alice, remove, {'password': 'wrong'}).status_code == 400
    resp = _post(auth_alice, remove, {'password': 'alicepass123'})
    assert resp.status_code == 200 and resp.json() == {'has_password': False}
    assert auth_alice.delete('/api/passkeys/%d/' % passkey.pk).status_code == 409
    assert _post(auth_alice, remove, {'password': 'alicepass123'}).status_code == 409


def test_remove_password_keeps_session_signed_in(client, alice, authenticator):
    add_passkey(alice, authenticator)
    client.force_login(alice)
    resp = client.post('/api/passkeys/password/remove/', {'password': 'alicepass123'},
                       content_type='application/json')
    assert resp.status_code == 200
    assert client.get('/api/passkeys/').status_code == 200
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_views.py -v --no-cov`
Expected: FAIL — account endpoint URLs return 404 (e.g. `assert 404 == 201`).

- [ ] **Step 3: Implement the account views**

In `app/user_data/passkey_views.py`, add to the imports:

```python
from django.contrib.auth import update_session_auth_hash
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from . import passkey_manage as manage
```

After `class PasskeyRateThrottle`, add:

```python


ACCOUNT_AUTHENTICATION = [TokenAuthentication, SessionAuthentication]
```

Append to the end of the module:

```python


def _lockout():
    return Response({'detail': _('Your account must keep at least one way to sign in.')},
                    status=status.HTTP_409_CONFLICT)


@api_view(['POST'])
@authentication_classes(ACCOUNT_AUTHENTICATION)
@permission_classes([IsAuthenticated])
@throttle_classes([PasskeyRateThrottle])
def register_begin(request):
    data = _data(request)
    try:
        service.verify_step_up(request.user, password=data.get('password'),
                               assertion=data.get('step_up'))
    except service.StepUpFailed:
        return Response({'detail': _('Re-authentication failed.')},
                        status=status.HTTP_400_BAD_REQUEST)
    return _ceremony(*service.begin_register(request.user))


@api_view(['POST'])
@authentication_classes(ACCOUNT_AUTHENTICATION)
@permission_classes([IsAuthenticated])
@throttle_classes([PasskeyRateThrottle])
def register_finish(request):
    data = _data(request)
    try:
        passkey = service.finish_register(request.user, data.get('challenge_id'),
                                          data.get('credential'), data.get('name'))
    except service.RegistrationFailed:
        return Response({'detail': _('Passkey registration failed.')},
                        status=status.HTTP_400_BAD_REQUEST)
    return Response(manage.passkey_to_dict(passkey), status=status.HTTP_201_CREATED)


@api_view(['GET'])
@authentication_classes(ACCOUNT_AUTHENTICATION)
@permission_classes([IsAuthenticated])
def passkey_list(request):
    return Response(manage.list_passkeys(request.user))


@api_view(['PATCH', 'DELETE'])
@authentication_classes(ACCOUNT_AUTHENTICATION)
@permission_classes([IsAuthenticated])
def passkey_detail(request, passkey_id):
    try:
        if request.method == 'DELETE':
            manage.delete_passkey(request.user, passkey_id)
            return Response(status=status.HTTP_204_NO_CONTENT)
        passkey = manage.rename_passkey(request.user, passkey_id, _data(request).get('name'))
    except manage.NotFound:
        return Response({'detail': _('Passkey not found.')}, status=status.HTTP_404_NOT_FOUND)
    except manage.InvalidName:
        return Response({'name': [_('Enter a name for this passkey.')]},
                        status=status.HTTP_400_BAD_REQUEST)
    except manage.LockoutGuard:
        return _lockout()
    return Response(manage.passkey_to_dict(passkey))


@api_view(['POST'])
@authentication_classes(ACCOUNT_AUTHENTICATION)
@permission_classes([IsAuthenticated])
@throttle_classes([PasskeyRateThrottle])
def password_remove(request):
    try:
        user = manage.remove_password(request.user, _data(request).get('password'))
    except manage.LockoutGuard:
        return _lockout()
    except manage.WrongPassword:
        return Response({'detail': _('Re-authentication failed.')},
                        status=status.HTTP_400_BAD_REQUEST)
    if isinstance(request.successful_authenticator, SessionAuthentication):
        # The session auth hash derives from the password hash; keep this browser signed in.
        update_session_auth_hash(request, user)
    return Response({'has_password': False})
```

- [ ] **Step 4: Route them**

In `app/etipitaka_auth/urls.py`, after the four passkey routes from Task 11 add:

```python
    path('api/passkeys/', passkey_views.passkey_list),
    path('api/passkeys/<int:passkey_id>/', passkey_views.passkey_detail),
    path('api/passkeys/register/begin/', passkey_views.register_begin),
    path('api/passkeys/register/finish/', passkey_views.register_finish),
    path('api/passkeys/password/remove/', passkey_views.password_remove),
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_views.py -v --no-cov`
Expected: 35 passed.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/passkey_views.py app/etipitaka_auth/urls.py app/user_data/tests/test_passkey_views.py
git commit -m "$(cat <<'EOF'
feat(passkey): account API to link passkeys with step-up and manage them

OAuth bearer tokens are not accepted on these endpoints.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---
### Task 13: Browser-session passkey login (`/login/passkey/`)

**Files:**
- Create: `app/user_data/passkey_web_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_passkey_web.py`

Why a plain Django view: DRF's `api_view` exempts CSRF unless `SessionAuthentication` authenticates the request, and this endpoint is anonymous. A plain view keeps Django's CSRF middleware in force, which blocks login CSRF.

- [ ] **Step 1: Write the failing tests**

Create `app/user_data/tests/test_passkey_web.py`:

```python
import json

import pytest
from django.test import Client

from .conftest import add_passkey

pytestmark = pytest.mark.django_db


def _assertion(client, authenticator, **tamper):
    begin = client.post('/api/passkeys/login/begin/', '{}',
                        content_type='application/json').json()
    return {'challenge_id': begin['challenge_id'],
            'credential': authenticator.assert_(begin['options'], **tamper)}


def _post_json(client, url, body, **extra):
    return client.post(url, json.dumps(body), content_type='application/json', **extra)


def test_web_login_starts_session_and_honours_next(client, alice, authenticator):
    add_passkey(alice, authenticator)
    body = dict(_assertion(client, authenticator), next='/o/authorize/?client_id=x')
    resp = _post_json(client, '/login/passkey/', body)
    assert resp.status_code == 200
    assert resp.json() == {'redirect': '/o/authorize/?client_id=x'}
    assert client.session['_auth_user_id'] == str(alice.pk)


@pytest.mark.parametrize('next_url', ['https://evil.example/', '//evil.example', '', None, 5])
def test_web_login_unsafe_next_falls_back_to_root(client, alice, authenticator, next_url):
    add_passkey(alice, authenticator)
    body = dict(_assertion(client, authenticator), next=next_url)
    assert _post_json(client, '/login/passkey/', body).json() == {'redirect': '/'}


def test_web_login_rejects_bad_assertion(client, alice, authenticator):
    add_passkey(alice, authenticator)
    resp = _post_json(client, '/login/passkey/',
                      _assertion(client, authenticator, corrupt_signature=True))
    assert resp.status_code == 400
    assert 'detail' in resp.json()
    assert '_auth_user_id' not in client.session


def test_web_login_inactive_account(client, alice, authenticator):
    add_passkey(alice, authenticator)
    alice.is_active = False
    alice.save()
    assert _post_json(client, '/login/passkey/', _assertion(client, authenticator)).status_code == 400


def test_web_login_requires_csrf(alice, authenticator):
    add_passkey(alice, authenticator)
    csrf_client = Client(enforce_csrf_checks=True)
    resp = _post_json(csrf_client, '/login/passkey/', _assertion(csrf_client, authenticator))
    assert resp.status_code == 403


def test_web_login_accepts_csrf_header(alice, authenticator):
    add_passkey(alice, authenticator)
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.get('/login/')
    token = csrf_client.cookies['csrftoken'].value
    resp = _post_json(csrf_client, '/login/passkey/', _assertion(csrf_client, authenticator),
                      HTTP_X_CSRFTOKEN=token)
    assert resp.status_code == 200


def test_web_login_rejects_get_and_garbage(client):
    assert client.get('/login/passkey/').status_code == 405
    assert client.post('/login/passkey/', 'not json',
                       content_type='application/json').status_code == 400
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_web.py -v --no-cov`
Expected: FAIL — `/login/passkey/` returns 404.

- [ ] **Step 3: Write the view**

Create `app/user_data/passkey_web_views.py`:

```python
"""Browser-session passkey endpoints.

Plain Django views, not DRF: api_view exempts CSRF unless SessionAuthentication
authenticates the request, and these endpoints are anonymous. Keeping Django's
CSRF middleware in force stops login CSRF (an attacker signing a victim's
browser into the attacker's account).
"""
import json

from django.contrib.auth import login
from django.http import JsonResponse
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from . import passkey_service as service
from .views import _safe_redirect_target

SESSION_BACKEND = 'django.contrib.auth.backends.ModelBackend'


def json_body(request):
    """The request's JSON object, or {} for anything else."""
    try:
        data = json.loads(request.body or b'{}')
    except (ValueError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


@require_POST
@csrf_protect
def login_passkey(request):
    data = json_body(request)
    try:
        user = service.finish_login(data.get('challenge_id'), data.get('credential'))
    except service.InactiveUser:
        return JsonResponse({'detail': _('This account is not active. Please verify your email.')},
                            status=400)
    except service.InvalidCredentials:
        return JsonResponse({'detail': _('Unable to log in with provided credentials.')},
                            status=400)
    login(request, user, backend=SESSION_BACKEND)
    next_url = data.get('next') if isinstance(data.get('next'), str) else ''
    return JsonResponse({'redirect': _safe_redirect_target(request, next_url)})
```

- [ ] **Step 4: Route it**

In `app/etipitaka_auth/urls.py`, add the import:

```python
from user_data import passkey_web_views
```

and directly after `path('login/', views.login_view),` add:

```python
    path('login/passkey/', passkey_web_views.login_passkey),
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_web.py -v --no-cov`
Expected: 11 passed.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/passkey_web_views.py app/etipitaka_auth/urls.py app/user_data/tests/test_passkey_web.py
git commit -m "$(cat <<'EOF'
feat(passkey): CSRF-protected browser session login honouring next

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: Apple and Android association files

**Files:**
- Create: `app/user_data/wellknown_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_wellknown.py`

- [ ] **Step 1: Write the failing tests**

Create `app/user_data/tests/test_wellknown.py`:

```python
AASA = '/.well-known/apple-app-site-association'
ASSETLINKS = '/.well-known/assetlinks.json'


def test_apple_app_site_association(client, settings):
    settings.PASSKEY_IOS_APP_IDS = ['A6DJDJ7527.com.watnapp.E-Tipitaka-Plus']
    resp = client.get(AASA)
    assert resp.status_code == 200
    assert resp['Content-Type'] == 'application/json'
    assert resp.json() == {'webcredentials': {'apps': ['A6DJDJ7527.com.watnapp.E-Tipitaka-Plus']}}


def test_assetlinks_json_404_when_android_unset(client):
    resp = client.get(ASSETLINKS)
    assert resp.status_code == 404
    assert resp['Content-Type'] == 'application/json'


def test_assetlinks_when_configured(client, settings):
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.etipitaka'
    settings.PASSKEY_ANDROID_CERT_SHA256 = ['AB:CD']
    assert client.get(ASSETLINKS).json() == [{
        'relation': ['delegate_permission/common.get_login_creds'],
        'target': {'namespace': 'android_app', 'package_name': 'com.watnapp.etipitaka',
                   'sha256_cert_fingerprints': ['AB:CD']}}]


def test_wellknown_rejects_post(client):
    assert client.post(AASA).status_code == 405
    assert client.post(ASSETLINKS).status_code == 405
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_wellknown.py -v --no-cov`
Expected: FAIL — AASA returns 404.

- [ ] **Step 3: Write the views**

Create `app/user_data/wellknown_views.py`:

```python
"""Association files that let the native apps use passkeys for this domain.

Only `webcredentials` is declared for iOS (no universal-link paths), so links
in emails always open in the browser.
"""
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET


@require_GET
def apple_app_site_association(request):
    return JsonResponse({'webcredentials': {'apps': list(settings.PASSKEY_IOS_APP_IDS)}})


@require_GET
def assetlinks(request):
    if not settings.PASSKEY_ANDROID_PACKAGE or not settings.PASSKEY_ANDROID_CERT_SHA256:
        # JSON rather than Django's HTML 404, which varies with DEBUG.
        return JsonResponse({'detail': 'Not found.'}, status=404)
    return JsonResponse([{
        'relation': ['delegate_permission/common.get_login_creds'],
        'target': {'namespace': 'android_app',
                   'package_name': settings.PASSKEY_ANDROID_PACKAGE,
                   'sha256_cert_fingerprints': list(settings.PASSKEY_ANDROID_CERT_SHA256)},
    }], safe=False)
```

- [ ] **Step 4: Route them**

In `app/etipitaka_auth/urls.py`, add the import:

```python
from user_data import wellknown_views
```

and after `path('.well-known/oauth-authorization-server', ...)` add:

```python
    path('.well-known/apple-app-site-association', wellknown_views.apple_app_site_association),
    path('.well-known/assetlinks.json', wellknown_views.assetlinks),
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_wellknown.py -v --no-cov`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/wellknown_views.py app/etipitaka_auth/urls.py app/user_data/tests/test_wellknown.py
git commit -m "$(cat <<'EOF'
feat(passkey): serve apple-app-site-association and assetlinks.json

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 15: Recovery backend (reset email for passkey-only users, token revocation)

**Files:**
- Create: `app/user_data/recovery.py`
- Create: `app/templates/registration/password_reset_email.txt`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_recovery.py`

- [ ] **Step 1: Write the failing tests**

Create `app/user_data/tests/test_recovery.py`:

```python
import re

import pytest
from django.core import mail
from oauth2_provider.models import AccessToken
from rest_framework.authtoken.models import Token

from user_data.recovery import recovery_token_generator

from .conftest import add_passkey, make_oauth_token

pytestmark = pytest.mark.django_db

LINK_RE = re.compile(r'/reset/(?P<uidb64>[^/\s]+)/(?P<token>[^/\s]+)/')


def _request_reset(client, email='alice@example.com'):
    resp = client.post('/password_reset/', {'email': email})
    assert resp.status_code == 302


def _open_link(client):
    """Follow the emailed link; return (uidb64, set-password URL)."""
    match = LINK_RE.search(mail.outbox[-1].body)
    resp = client.get(match.group(0))
    assert resp.status_code == 302
    assert resp['Location'].endswith('/set-password/')
    return match.group('uidb64'), resp['Location']


def test_reset_email_sent_to_passkey_only_user(client, alice, authenticator):
    add_passkey(alice, authenticator)
    alice.set_unusable_password()
    alice.save()
    mail.outbox.clear()
    _request_reset(client)
    assert len(mail.outbox) == 1
    assert LINK_RE.search(mail.outbox[0].body)


def test_reset_email_not_sent_to_inactive_user(client, alice):
    alice.is_active = False
    alice.save()
    _request_reset(client)
    assert mail.outbox == []


def test_token_invalidated_by_new_passkey(alice, authenticator):
    token = recovery_token_generator.make_token(alice)
    assert recovery_token_generator.check_token(alice, token)
    add_passkey(alice, authenticator)
    assert not recovery_token_generator.check_token(alice, token)


def test_password_reset_revokes_tokens(client, alice):
    make_oauth_token(alice)
    _request_reset(client)
    _uidb64, set_password_url = _open_link(client)
    resp = client.post(set_password_url, {'new_password1': 'N3w-pass-phrase!',
                                          'new_password2': 'N3w-pass-phrase!'})
    assert resp.status_code == 302
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    alice.refresh_from_db()
    assert alice.check_password('N3w-pass-phrase!')


def test_confirm_page_context_has_uidb64(client, alice):
    _request_reset(client)
    uidb64, set_password_url = _open_link(client)
    page = client.get(set_password_url)
    assert page.context['validlink'] is True
    assert page.context['uidb64'] == uidb64
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_recovery.py -v --no-cov`
Expected: FAIL — `ModuleNotFoundError: No module named 'user_data.recovery'`.

- [ ] **Step 3: Write the recovery email template**

Create `app/templates/registration/password_reset_email.txt`:

```
{% load i18n %}{% autoescape off %}{% blocktrans with username=user.get_username %}Hello {{ username }},{% endblocktrans %}

{% trans "We received a request to recover your E-Tipitaka account." %}
{% trans "Open the link below to set a new password or create a new passkey:" %}

{{ protocol }}://{{ domain }}{% url 'password_reset_confirm' uidb64=uid token=token %}

{% trans "If you did not ask for this, you can ignore this e-mail." %}

-- E-Tipitaka
{% endautoescape %}
```

- [ ] **Step 4: Write the recovery module**

Create `app/user_data/recovery.py`:

```python
"""Account recovery built on Django's password reset.

Extensions: users without a usable password (passkey-only accounts) get the
reset email too; the link also dies once a passkey is added; completing any
recovery revokes every API token so a lost device loses access; and the
confirm page can create a new passkey instead of setting a password.
"""
from django.contrib.auth.forms import PasswordResetForm, _unicode_ci_compare
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.views import PasswordResetConfirmView, PasswordResetView

from .account_tokens import revoke_all_tokens


class AccountRecoveryTokenGenerator(PasswordResetTokenGenerator):
    """Reset token that is also spent once a passkey is added."""
    key_salt = 'user_data.recovery.AccountRecoveryTokenGenerator'

    def _make_hash_value(self, user, timestamp):
        newest = user.passkeys.order_by('-pk').values_list('pk', flat=True).first()
        return super()._make_hash_value(user, timestamp) + str(newest or '')


recovery_token_generator = AccountRecoveryTokenGenerator()


class AccountRecoveryForm(PasswordResetForm):
    def get_users(self, email):
        """Active users with this email, with or without a usable password."""
        email_field = User.get_email_field_name()
        users = User._default_manager.filter(
            **{'%s__iexact' % email_field: email, 'is_active': True})
        return (u for u in users if _unicode_ci_compare(email, getattr(u, email_field)))


password_reset_view = PasswordResetView.as_view(
    form_class=AccountRecoveryForm, token_generator=recovery_token_generator,
    email_template_name='registration/password_reset_email.txt')


class AccountRecoveryConfirmView(PasswordResetConfirmView):
    token_generator = recovery_token_generator

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['uidb64'] = self.kwargs['uidb64']
        return context

    def form_valid(self, form):
        response = super().form_valid(form)
        revoke_all_tokens(form.user)
        return response
```

- [ ] **Step 5: Route it ahead of Django's auth URLs**

In `app/etipitaka_auth/urls.py`, add the import:

```python
from user_data import recovery
```

and directly **before** `path('', include('django.contrib.auth.urls')),` add:

```python
    # Override Django's reset views (same names) with the recovery versions.
    path('password_reset/', recovery.password_reset_view, name='password_reset'),
    path('reset/<uidb64>/<token>/', recovery.AccountRecoveryConfirmView.as_view(),
         name='password_reset_confirm'),
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_recovery.py user_data/tests/test_views.py -v --no-cov`
Expected: all passed (5 new recovery tests; existing view tests unaffected).

- [ ] **Step 7: Commit**

```bash
git add app/user_data/recovery.py app/templates/registration/password_reset_email.txt app/etipitaka_auth/urls.py app/user_data/tests/test_recovery.py
git commit -m "$(cat <<'EOF'
feat(recovery): reset email reaches passkey-only users and revokes tokens

A completed password reset now revokes the user's DRF and OAuth tokens,
so other devices must sign in again.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 16: Recovery passkey endpoints

**Files:**
- Modify: `app/user_data/recovery.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_recovery.py`

- [ ] **Step 1: Write the failing tests**

In `app/user_data/tests/test_recovery.py`, add to the imports:

```python
import json

from django.test import Client
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
```

Append:

```python


def _begin_recovery(client, uidb64):
    return client.post('/account/recover/passkey/begin/', json.dumps({'uidb64': uidb64}),
                       content_type='application/json')


def _recover_with_passkey(client, uidb64, authenticator, **tamper):
    begin = _begin_recovery(client, uidb64)
    assert begin.status_code == 200, begin.content
    body = begin.json()
    return client.post('/account/recover/passkey/finish/', json.dumps({
        'uidb64': uidb64, 'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options'], **tamper)}),
        content_type='application/json')


def test_passkey_recovery_signs_in_and_revokes_tokens(client, alice, authenticator):
    alice.set_unusable_password()
    alice.save()
    make_oauth_token(alice)
    _request_reset(client)
    uidb64, set_password_url = _open_link(client)
    resp = _recover_with_passkey(client, uidb64, authenticator)
    assert resp.status_code == 200
    assert resp.json() == {'redirect': '/account/security/'}
    assert client.session['_auth_user_id'] == str(alice.pk)
    assert alice.passkeys.count() == 1
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert client.get(set_password_url).context['validlink'] is False  # link spent


def test_passkey_recovery_requires_reset_session(client, alice):
    uidb64 = urlsafe_base64_encode(force_bytes(alice.pk))
    assert _begin_recovery(client, uidb64).status_code == 400


@pytest.mark.parametrize('uidb64', [None, 5, '!!!', 'YWJj'])
def test_passkey_recovery_rejects_bad_uid(client, alice, uidb64):
    _request_reset(client)
    _open_link(client)
    assert _begin_recovery(client, uidb64).status_code == 400


def test_passkey_recovery_rejects_other_users_uid(client, alice, bob):
    _request_reset(client)
    _open_link(client)
    assert _begin_recovery(client, urlsafe_base64_encode(force_bytes(bob.pk))).status_code == 400


def test_passkey_recovery_rejects_inactive_user(client, alice):
    _request_reset(client)
    uidb64, _url = _open_link(client)
    alice.is_active = False
    alice.save()
    assert _begin_recovery(client, uidb64).status_code == 400


def test_passkey_recovery_bad_response_keeps_link(client, alice, authenticator):
    _request_reset(client)
    uidb64, set_password_url = _open_link(client)
    resp = _recover_with_passkey(client, uidb64, authenticator, uv=False)
    assert resp.status_code == 400
    assert client.get(set_password_url).context['validlink'] is True


def test_passkey_recovery_finish_rejects_without_session(client, alice):
    uidb64 = urlsafe_base64_encode(force_bytes(alice.pk))
    resp = client.post('/account/recover/passkey/finish/', json.dumps({'uidb64': uidb64}),
                       content_type='application/json')
    assert resp.status_code == 400


def test_passkey_recovery_requires_csrf():
    csrf_client = Client(enforce_csrf_checks=True)
    resp = csrf_client.post('/account/recover/passkey/begin/', '{}',
                            content_type='application/json')
    assert resp.status_code == 403
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_recovery.py -v --no-cov`
Expected: FAIL — `/account/recover/passkey/begin/` returns 404.

- [ ] **Step 3: Implement the endpoints**

In `app/user_data/recovery.py`, replace the imports with:

```python
from django.contrib.auth import login
from django.contrib.auth.forms import PasswordResetForm, _unicode_ci_compare
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.views import (INTERNAL_RESET_SESSION_TOKEN,
                                       PasswordResetConfirmView, PasswordResetView)
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.utils.http import urlsafe_base64_decode
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from . import passkey_service as service
from .account_tokens import revoke_all_tokens
from .passkey_web_views import SESSION_BACKEND, json_body
```

Append to the end of the module:

```python


def _recovering_user(request, uidb64):
    """The active user whose valid reset token this session holds, else None."""
    if not isinstance(uidb64, str):
        return None
    try:
        user = User._default_manager.get(pk=urlsafe_base64_decode(uidb64).decode())
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
        return None
    token = request.session.get(INTERNAL_RESET_SESSION_TOKEN)
    if not user.is_active or not recovery_token_generator.check_token(user, token):
        return None
    return user


def _invalid_link():
    return JsonResponse({'detail': _('This password reset link is invalid or has expired.')},
                        status=400)


@require_POST
@csrf_protect
def recover_passkey_begin(request):
    user = _recovering_user(request, json_body(request).get('uidb64'))
    if user is None:
        return _invalid_link()
    challenge_id, options = service.begin_recover(user)
    return JsonResponse({'challenge_id': challenge_id, 'options': options})


@require_POST
@csrf_protect
def recover_passkey_finish(request):
    data = json_body(request)
    user = _recovering_user(request, data.get('uidb64'))
    if user is None:
        return _invalid_link()
    try:
        service.finish_recover(user, data.get('challenge_id'), data.get('credential'),
                               data.get('name'))
    except service.RegistrationFailed:
        return JsonResponse({'detail': _('Passkey registration failed.')}, status=400)
    request.session.pop(INTERNAL_RESET_SESSION_TOKEN, None)
    login(request, user, backend=SESSION_BACKEND)
    return JsonResponse({'redirect': '/account/security/'})
```

- [ ] **Step 4: Route them**

In `app/etipitaka_auth/urls.py`, after the `re_path(r'^account/confirm-email/...` entry add:

```python
    path('account/recover/passkey/begin/', recovery.recover_passkey_begin),
    path('account/recover/passkey/finish/', recovery.recover_passkey_finish),
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_recovery.py -v --no-cov`
Expected: 16 passed.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/recovery.py app/etipitaka_auth/urls.py app/user_data/tests/test_recovery.py
git commit -m "$(cat <<'EOF'
feat(recovery): create a new passkey from a password-reset link

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 17: Shared browser helper and base layout

**Files:**
- Create: `app/assets/passkey.js`
- Modify: `app/templates/base.html` (style block ~line 23; navbar logout form ~line 54; `window.i18n` ~line 76)
- Test: `app/user_data/tests/test_passkey_pages.py`

- [ ] **Step 1: Write the failing tests**

Create `app/user_data/tests/test_passkey_pages.py`:

```python
import pytest

pytestmark = pytest.mark.django_db


def test_base_has_hidden_rule_and_passkey_i18n(client):
    html = client.get('/login/').content.decode()
    assert '[hidden] { display: none !important; }' in html
    assert 'passkeyCancelled:' in html


def test_navbar_links_security_page_when_signed_in(client, alice):
    client.force_login(alice)
    assert 'href="/account/security/"' in client.get('/user_data/').content.decode()


def test_navbar_hides_security_link_when_signed_out(client):
    assert 'href="/account/security/"' not in client.get('/login/').content.decode()
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_pages.py -v --no-cov`
Expected: FAIL on the first two tests.

- [ ] **Step 3: Update base.html**

In `app/templates/base.html`:

Replace
```html
        .checkbox-list { border:2px solid #ccc; width:300px; height: 350px; overflow-y: scroll; }
```
with
```html
        .checkbox-list { border:2px solid #ccc; width:300px; height: 350px; overflow-y: scroll; }
        [hidden] { display: none !important; }
```

Replace
```html
        <span ng-controller="UserDataController" class="btn btn-primary" ng-click="upload()">{% trans "Upload" %}</span>
```
with
```html
        <span ng-controller="UserDataController" class="btn btn-primary" ng-click="upload()">{% trans "Upload" %}</span>
        <a class="btn btn-link" href="/account/security/">{% trans "Security" %}</a>
```

Replace
```html
        signupGenericError: "{% filter escapejs %}{% trans 'Something went wrong. Please try again.' %}{% endfilter %}"
```
with
```html
        signupGenericError: "{% filter escapejs %}{% trans 'Something went wrong. Please try again.' %}{% endfilter %}",
        passkeyCancelled: "{% filter escapejs %}{% trans 'The passkey request was cancelled.' %}{% endfilter %}"
```

- [ ] **Step 4: Write the shared helper**

Create `app/assets/passkey.js`:

```javascript
/* Passkey (WebAuthn) helpers shared by the login, signup, security and
 * recovery pages. Vanilla JS on purpose: base.html boots AngularJS, and
 * nothing here may be interpolated by it. Server-provided text is only ever
 * inserted with textContent. */
(function (window, document) {
  'use strict';

  function b64urlToBuffer(value) {
    var base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    var binary = window.atob(base64 + '==='.slice((base64.length + 3) % 4));
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
    return bytes.buffer;
  }

  function bufferToB64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) { binary += String.fromCharCode(bytes[i]); }
    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function withIds(list) {
    return (list || []).map(function (item) {
      return Object.assign({}, item, {id: b64urlToBuffer(item.id)});
    });
  }

  function creationOptions(json) {
    if (window.PublicKeyCredential.parseCreationOptionsFromJSON) {
      return window.PublicKeyCredential.parseCreationOptionsFromJSON(json);
    }
    return Object.assign({}, json, {
      challenge: b64urlToBuffer(json.challenge),
      user: Object.assign({}, json.user, {id: b64urlToBuffer(json.user.id)}),
      excludeCredentials: withIds(json.excludeCredentials)
    });
  }

  function requestOptions(json) {
    if (window.PublicKeyCredential.parseRequestOptionsFromJSON) {
      return window.PublicKeyCredential.parseRequestOptionsFromJSON(json);
    }
    return Object.assign({}, json, {
      challenge: b64urlToBuffer(json.challenge),
      allowCredentials: withIds(json.allowCredentials)
    });
  }

  function credentialToJSON(credential) {
    if (typeof credential.toJSON === 'function') { return credential.toJSON(); }
    var response = credential.response;
    var out = {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {clientDataJSON: bufferToB64url(response.clientDataJSON)}
    };
    if (response.attestationObject) {
      out.response.attestationObject = bufferToB64url(response.attestationObject);
      out.response.transports = response.getTransports ? response.getTransports() : [];
    } else {
      out.response.authenticatorData = bufferToB64url(response.authenticatorData);
      out.response.signature = bufferToB64url(response.signature);
      if (response.userHandle) { out.response.userHandle = bufferToB64url(response.userHandle); }
    }
    return out;
  }

  function csrfToken() {
    var input = document.querySelector('input[name=csrfmiddlewaretoken]');
    return input ? input.value : '';
  }

  function request(method, url, body) {
    var init = {method: method, credentials: 'same-origin',
                headers: {'Accept': 'application/json', 'X-CSRFToken': csrfToken()}};
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    return window.fetch(url, init).then(function (resp) {
      return resp.text().then(function (text) {
        var data = {};
        try { data = text ? JSON.parse(text) : {}; } catch (e) { data = {}; }
        if (!resp.ok) {
          var err = new Error('HTTP ' + resp.status);
          err.status = resp.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  function postJSON(url, body) { return request('POST', url, body || {}); }

  /* begin -> navigator.credentials.create -> finish; resolves with finish's JSON. */
  function create(beginUrl, finishUrl, beginBody, finishExtra) {
    return postJSON(beginUrl, beginBody).then(function (begin) {
      return navigator.credentials.create({publicKey: creationOptions(begin.options)})
        .then(function (credential) {
          return postJSON(finishUrl, Object.assign({
            challenge_id: begin.challenge_id,
            credential: credentialToJSON(credential)
          }, finishExtra || {}));
        });
    });
  }

  /* Login challenge + navigator.credentials.get; resolves with {challenge_id, credential}. */
  function assertion(mediation, signal) {
    return postJSON('/api/passkeys/login/begin/').then(function (begin) {
      var args = {publicKey: requestOptions(begin.options)};
      if (mediation) { args.mediation = mediation; }
      if (signal) { args.signal = signal; }
      return navigator.credentials.get(args).then(function (credential) {
        return {challenge_id: begin.challenge_id, credential: credentialToJSON(credential)};
      });
    });
  }

  function errorMessage(err) {
    if (err && err.name === 'NotAllowedError') { return window.i18n.passkeyCancelled; }
    var data = err && err.data;
    if (data) {
      if (data.detail) { return String(data.detail); }
      var keys = Object.keys(data);
      if (keys.length && Array.isArray(data[keys[0]]) && data[keys[0]].length) {
        return String(data[keys[0]][0]);
      }
    }
    return window.i18n.signupGenericError;
  }

  window.Passkey = {
    supported: !!(window.PublicKeyCredential && navigator.credentials && window.fetch),
    request: request,
    postJSON: postJSON,
    create: create,
    assertion: assertion,
    errorMessage: errorMessage
  };
})(window, document);
```

- [ ] **Step 5: Check syntax and run the tests**

Run:
```bash
node --check app/assets/passkey.js
docker compose exec -T web python -m pytest user_data/tests/test_passkey_pages.py -v --no-cov
```
Expected: `node` prints nothing (exit 0); 3 passed.

- [ ] **Step 6: Commit**

```bash
git add app/assets/passkey.js app/templates/base.html app/user_data/tests/test_passkey_pages.py
git commit -m "$(cat <<'EOF'
feat(passkey): shared browser WebAuthn helper and security navbar link

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 18: Login page — passkey button and autofill

**Files:**
- Modify: `app/templates/forms/login_form.html`
- Modify: `app/templates/login.html`
- Create: `app/assets/passkey_login.js`
- Test: `app/user_data/tests/test_passkey_pages.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_passkey_pages.py`:

```python


def test_login_page_has_passkey_controls(client):
    html = client.get('/login/').content.decode()
    assert 'id="passkey-login-button"' in html
    assert 'autocomplete="username webauthn"' in html
    assert 'autocomplete="current-password"' in html
    assert '/static/passkey.js' in html
    assert '/static/passkey_login.js' in html
```

- [ ] **Step 2: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_pages.py -v --no-cov -k login_page`
Expected: FAIL.

- [ ] **Step 3: Update the login form**

In `app/templates/forms/login_form.html`:

Replace the opening
```html
{% load i18n %}
<div>
```
with
```html
{% load i18n %}
<div>
{# ng-non-bindable: error text is inserted by passkey_login.js; AngularJS must never interpolate it. #}
<div id="passkey-login" class="form-group row" hidden ng-non-bindable>
  <div class="col-sm-offset-2 col-sm-6">
    <button type="button" class="btn btn-primary" id="passkey-login-button">{% trans "Sign in with a passkey" %}</button>
    <br/><span class="error-msg" id="passkey-login-error"></span>
  </div>
</div>
```

Replace the username input line
```html
      <input required name="username" type="text" class="form-control" id="username" placeholder="{% trans 'Username' %}">
```
with
```html
      <input required name="username" type="text" class="form-control" id="username" placeholder="{% trans 'Username' %}" autocomplete="username webauthn">
```

Replace the password input line
```html
      <input required name="password" type="password" class="form-control" id="password" placeholder="{% trans 'Password' %}">
```
with
```html
      <input required name="password" type="password" class="form-control" id="password" placeholder="{% trans 'Password' %}" autocomplete="current-password">
```

- [ ] **Step 4: Load the scripts on the login page**

Append to `app/templates/login.html`:

```html

{% block script %}
<script src="{% static 'passkey.js' %}"></script>
<script src="{% static 'passkey_login.js' %}"></script>
{% endblock %}
```

- [ ] **Step 5: Write the login page script**

Create `app/assets/passkey_login.js`:

```javascript
/* Login page: "Sign in with a passkey" button plus browser autofill
 * (conditional mediation) on the username field. */
(function (window, document) {
  'use strict';
  var P = window.Passkey;
  var box = document.getElementById('passkey-login');
  if (!box || !P.supported) { return; }
  box.hidden = false;

  var button = document.getElementById('passkey-login-button');
  var errorEl = document.getElementById('passkey-login-error');
  var nextInput = document.querySelector('input[name=next]');
  var controller = null;
  var timer = null;

  function finish(result) {
    return P.postJSON('/login/passkey/', {
      challenge_id: result.challenge_id,
      credential: result.credential,
      next: nextInput ? nextInput.value : ''
    }).then(function (data) { window.location.assign(data.redirect); });
  }

  function stopAutofill() {
    window.clearTimeout(timer);
    if (controller) { controller.abort(); controller = null; }
  }

  function startAutofill() {
    var PKC = window.PublicKeyCredential;
    if (!PKC.isConditionalMediationAvailable) { return; }
    PKC.isConditionalMediationAvailable().then(function (available) {
      if (!available) { return; }
      stopAutofill();
      var mine = controller = new AbortController();
      // Challenges expire server-side after 5 minutes; refresh just before.
      timer = window.setTimeout(startAutofill, 270000);
      P.assertion('conditional', mine.signal).then(finish).catch(function (err) {
        if (mine.signal.aborted) { return; }
        errorEl.textContent = P.errorMessage(err);
      });
    });
  }

  button.addEventListener('click', function () {
    errorEl.textContent = '';
    stopAutofill();
    P.assertion(null, null).then(finish).catch(function (err) {
      errorEl.textContent = P.errorMessage(err);
      startAutofill();
    });
  });

  startAutofill();
})(window, document);
```

- [ ] **Step 6: Check syntax and run the tests**

Run:
```bash
node --check app/assets/passkey_login.js
docker compose exec -T web python -m pytest user_data/tests/test_passkey_pages.py user_data/tests/test_views.py -v --no-cov
```
Expected: exit 0; all passed.

- [ ] **Step 7: Commit**

```bash
git add app/templates/forms/login_form.html app/templates/login.html app/assets/passkey_login.js app/user_data/tests/test_passkey_pages.py
git commit -m "$(cat <<'EOF'
feat(passkey): passkey sign-in button and autofill on the login page

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 19: Signup page — passkey signup with password fallback

**Files:**
- Modify: `app/templates/signup.html`
- Create: `app/assets/passkey_signup.js`
- Test: `app/user_data/tests/test_passkey_pages.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_passkey_pages.py`:

```python


def test_signup_page_has_passkey_form_and_password_fallback(client):
    html = client.get('/signup/').content.decode()
    assert 'id="passkey-signup-form"' in html
    assert 'id="password-signup"' in html
    assert 'id="show-password-signup"' in html
    assert '/static/passkey_signup.js' in html
```

- [ ] **Step 2: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_pages.py -v --no-cov -k signup_page`
Expected: FAIL.

- [ ] **Step 3: Replace the signup page**

Replace the whole of `app/templates/signup.html` with:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block title %}{% trans "Registration" %}{% endblock %}

{% block body %}
<div ng-controller="RegisterController" class="container">
    <h1>{% trans "Registration" %}</h1>
    <br/>
    <script type="text/ng-template" id="loadingModalContent.html">
        <div class="modal-body" style="text-align:center;">
            <div class="spinner-loader" style="text-align:center;">
                {% trans "Loading..." %}
            </div>
            <div style="text-align:center">
                {% trans "Loading..." %}
            </div>
        </div>
    </script>
    {# Shown by passkey_signup.js when the browser supports passkeys. ng-non-bindable: its text is set by that script. #}
    <div id="passkey-signup" hidden ng-non-bindable>
      <form class="form-horizontal" id="passkey-signup-form" role="form">
        <div class="form-group row">
          <label for="passkey-email" class="col-sm-2 control-label">{% trans "Email" %}</label>
          <div class="col-sm-6">
            <input required name="email" type="email" class="form-control" id="passkey-email" placeholder="{% trans 'Email' %}" autocomplete="email">
          </div>
        </div>
        <div class="form-group row">
          <label for="passkey-username" class="col-sm-2 control-label">{% trans "Username" %}</label>
          <div class="col-sm-6">
            <input required name="username" type="text" class="form-control" id="passkey-username" placeholder="{% trans 'Username' %}" autocomplete="username">
          </div>
        </div>
        <div class="form-group row">
          <div class="col-sm-offset-2 col-sm-10">
            <button type="submit" class="btn btn-primary">{% trans "Create account with a passkey" %}</button>
            <br/><span class="error-msg" id="passkey-signup-error"></span>
            <p><a href="#" id="show-password-signup">{% trans "Sign up with a password instead" %}</a></p>
          </div>
        </div>
      </form>
    </div>
    <div id="password-signup">
    {% include "forms/signup_form.html" %}
    </div>
</div>
{% endblock %}

{% block script %}
<script src="{% static 'passkey.js' %}"></script>
<script src="{% static 'passkey_signup.js' %}"></script>
{% endblock %}
```

- [ ] **Step 4: Write the signup page script**

Create `app/assets/passkey_signup.js`:

```javascript
/* Signup page: passkey signup by default, the password form as a fallback. */
(function (window, document) {
  'use strict';
  var P = window.Passkey;
  var box = document.getElementById('passkey-signup');
  var passwordBox = document.getElementById('password-signup');
  if (!box || !passwordBox || !P.supported) { return; }
  box.hidden = false;
  passwordBox.hidden = true;

  var errorEl = document.getElementById('passkey-signup-error');

  document.getElementById('show-password-signup').addEventListener('click', function (event) {
    event.preventDefault();
    box.hidden = true;
    passwordBox.hidden = false;
  });

  document.getElementById('passkey-signup-form').addEventListener('submit', function (event) {
    event.preventDefault();
    errorEl.textContent = '';
    P.create('/api/passkeys/signup/begin/', '/api/passkeys/signup/finish/', {
      username: document.getElementById('passkey-username').value,
      email: document.getElementById('passkey-email').value
    }).then(function () {
      window.location.assign('/signup/validate/');
    }).catch(function (err) {
      errorEl.textContent = P.errorMessage(err);
    });
  });
})(window, document);
```

- [ ] **Step 5: Check syntax and run the tests**

Run:
```bash
node --check app/assets/passkey_signup.js
docker compose exec -T web python -m pytest user_data/tests/test_passkey_pages.py -v --no-cov
```
Expected: exit 0; 5 passed.

- [ ] **Step 6: Commit**

```bash
git add app/templates/signup.html app/assets/passkey_signup.js app/user_data/tests/test_passkey_pages.py
git commit -m "$(cat <<'EOF'
feat(passkey): passkey signup form with password fallback

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 20: Account security page

**Files:**
- Modify: `app/user_data/passkey_web_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Create: `app/templates/account_security.html`
- Create: `app/assets/account_security.js`
- Test: `app/user_data/tests/test_passkey_pages.py`

- [ ] **Step 1: Write the failing tests**

Append to `app/user_data/tests/test_passkey_pages.py`:

```python


def test_security_page_requires_login(client):
    resp = client.get('/account/security/')
    assert resp.status_code == 302
    assert resp['Location'] == '/login/?next=/account/security/'


def test_security_page_renders(client, alice):
    client.force_login(alice)
    resp = client.get('/account/security/')
    html = resp.content.decode()
    assert resp.status_code == 200
    assert 'id="passkey-rows"' in html
    assert 'id="security" ng-non-bindable' in html
    assert 'csrfmiddlewaretoken' in html
    assert '/static/account_security.js' in html
    assert 'csrftoken' in resp.cookies
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_pages.py -v --no-cov -k security_page`
Expected: FAIL — 404.

- [ ] **Step 3: Add the view and route**

In `app/user_data/passkey_web_views.py`, add to the imports:

```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
```

Append:

```python


@login_required
@ensure_csrf_cookie
def account_security(request):
    return render(request, 'account_security.html', {})
```

In `app/etipitaka_auth/urls.py`, after `path('login/passkey/', ...)` add:

```python
    path('account/security/', passkey_web_views.account_security),
```

- [ ] **Step 4: Write the template**

Create `app/templates/account_security.html`:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block title %}{% trans "Sign-in and security" %}{% endblock %}

{% block body %}
{# ng-non-bindable: passkey names are user-controlled and inserted by account_security.js. #}
<div class="container" id="security" ng-non-bindable
     data-never="{% trans 'Never' %}"
     data-synced="{% trans 'Synced' %}"
     data-device-bound="{% trans 'This device only' %}"
     data-rename="{% trans 'Rename' %}"
     data-remove="{% trans 'Delete' %}"
     data-rename-prompt="{% trans 'New name for this passkey' %}"
     data-has-password="{% trans 'Your account has a password.' %}"
     data-no-password="{% trans 'Your account has no password. You sign in with a passkey.' %}">
  {% csrf_token %}
  <h1>{% trans "Sign-in and security" %}</h1>
  <p class="label label-warning" id="passkey-unsupported" hidden>{% trans "This browser does not support passkeys." %}</p>

  <h3>{% trans "Passkeys" %}</h3>
  <table class="table table-striped">
    <thead>
      <tr>
        <th>{% trans "Name" %}</th>
        <th>{% trans "Type" %}</th>
        <th>{% trans "Created" %}</th>
        <th>{% trans "Last used" %}</th>
        <th></th>
      </tr>
    </thead>
    <tbody id="passkey-rows"></tbody>
  </table>
  <p id="passkey-empty" hidden>{% trans "You have no passkeys yet." %}</p>
  <div id="add-passkey" class="form-inline" hidden>
    <span id="step-up-password" hidden>
      <label for="step-up-password-input">{% trans "Current password" %}</label>
      <input type="password" id="step-up-password-input" class="form-control" autocomplete="current-password">
    </span>
    <button type="button" class="btn btn-primary" id="add-passkey-button">{% trans "Add a passkey" %}</button>
  </div>

  <h3>{% trans "Password" %}</h3>
  <p id="password-status"></p>
  <div id="remove-password" class="form-inline" hidden>
    <label for="remove-password-input">{% trans "Current password" %}</label>
    <input type="password" id="remove-password-input" class="form-control" autocomplete="current-password">
    <button type="button" class="btn btn-danger" id="remove-password-button">{% trans "Remove password" %}</button>
  </div>

  <p class="error-msg" id="security-error"></p>
</div>
{% endblock %}

{% block script %}
<script src="{% static 'passkey.js' %}"></script>
<script src="{% static 'account_security.js' %}"></script>
{% endblock %}
```

- [ ] **Step 5: Write the page script**

Create `app/assets/account_security.js`:

```javascript
/* Account security page: list, add (after step-up), rename and delete
 * passkeys; remove the password once a passkey exists. */
(function (window, document) {
  'use strict';
  var P = window.Passkey;
  var root = document.getElementById('security');
  if (!root) { return; }
  var t = root.dataset;  // translated strings rendered by Django
  var rows = document.getElementById('passkey-rows');
  var errorEl = document.getElementById('security-error');
  var state = {has_password: false, passkeys: []};

  function $(id) { return document.getElementById(id); }

  function fail(err) { errorEl.textContent = P.errorMessage(err); }

  function formatDate(value) { return value ? new Date(value).toLocaleString() : t.never; }

  function cell(text) {
    var td = document.createElement('td');
    td.textContent = text;
    return td;
  }

  function actionButton(label, cls, onClick) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-xs ' + cls;
    b.textContent = label;
    b.addEventListener('click', onClick);
    return b;
  }

  function render() {
    rows.textContent = '';
    state.passkeys.forEach(function (passkey) {
      var tr = document.createElement('tr');
      var kind = passkey.backed_up ? t.synced : t.deviceBound;
      tr.appendChild(cell(passkey.name));
      tr.appendChild(cell(passkey.authenticator ? passkey.authenticator + ' · ' + kind : kind));
      tr.appendChild(cell(formatDate(passkey.created_at)));
      tr.appendChild(cell(formatDate(passkey.last_used_at)));
      var actions = document.createElement('td');
      actions.appendChild(actionButton(t.rename, 'btn-default', function () { rename(passkey); }));
      actions.appendChild(document.createTextNode(' '));
      actions.appendChild(actionButton(t.remove, 'btn-danger', function () { remove(passkey); }));
      tr.appendChild(actions);
      rows.appendChild(tr);
    });
    $('passkey-empty').hidden = state.passkeys.length > 0;
    $('passkey-unsupported').hidden = P.supported;
    $('add-passkey').hidden = !P.supported;
    $('step-up-password').hidden = !state.has_password;
    $('password-status').textContent = state.has_password ? t.hasPassword : t.noPassword;
    $('remove-password').hidden = !(state.has_password && state.passkeys.length > 0);
  }

  function load() {
    return P.request('GET', '/api/passkeys/').then(function (data) {
      state = data;
      render();
    }).catch(fail);
  }

  function rename(passkey) {
    var name = window.prompt(t.renamePrompt, passkey.name);
    if (name === null) { return; }
    errorEl.textContent = '';
    P.request('PATCH', '/api/passkeys/' + passkey.id + '/', {name: name}).then(load).catch(fail);
  }

  function remove(passkey) {
    if (!window.confirm(window.i18n.confirmDelete)) { return; }
    errorEl.textContent = '';
    P.request('DELETE', '/api/passkeys/' + passkey.id + '/').then(load).catch(fail);
  }

  function stepUp() {
    if (state.has_password) {
      return Promise.resolve({password: $('step-up-password-input').value});
    }
    return P.assertion(null, null).then(function (proof) { return {step_up: proof}; });
  }

  $('add-passkey-button').addEventListener('click', function () {
    errorEl.textContent = '';
    stepUp().then(function (proof) {
      return P.create('/api/passkeys/register/begin/', '/api/passkeys/register/finish/', proof);
    }).then(function () {
      $('step-up-password-input').value = '';
      return load();
    }).catch(fail);
  });

  $('remove-password-button').addEventListener('click', function () {
    errorEl.textContent = '';
    var input = $('remove-password-input');
    P.postJSON('/api/passkeys/password/remove/', {password: input.value}).then(function () {
      input.value = '';
      return load();
    }).catch(fail);
  });

  load();
})(window, document);
```

- [ ] **Step 6: Check syntax and run the tests**

Run:
```bash
node --check app/assets/account_security.js
docker compose exec -T web python -m pytest user_data/tests/test_passkey_pages.py -v --no-cov
```
Expected: exit 0; 7 passed.

- [ ] **Step 7: Commit**

```bash
git add app/user_data/passkey_web_views.py app/etipitaka_auth/urls.py app/templates/account_security.html app/assets/account_security.js app/user_data/tests/test_passkey_pages.py
git commit -m "$(cat <<'EOF'
feat(passkey): account security page to manage passkeys and password

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 21: Recovery confirm page — "Create a new passkey"

**Files:**
- Modify: `app/templates/registration/password_reset_confirm.html`
- Create: `app/assets/passkey_recover.js`
- Test: `app/user_data/tests/test_recovery.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_recovery.py`:

```python


def test_confirm_page_offers_passkey_button(client, alice):
    _request_reset(client)
    uidb64, set_password_url = _open_link(client)
    html = client.get(set_password_url).content.decode()
    assert 'id="passkey-recover-button"' in html
    assert 'data-uidb64="%s"' % uidb64 in html
    assert '/static/passkey_recover.js' in html
```

- [ ] **Step 2: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_recovery.py -v --no-cov -k passkey_button`
Expected: FAIL.

- [ ] **Step 3: Update the confirm template**

In `app/templates/registration/password_reset_confirm.html`, replace

```html
    {% if validlink %}
    <form class="form-horizontal" method="post" action="">{% csrf_token %}
```
with
```html
    {% if validlink %}
    {# ng-non-bindable: error text is inserted by passkey_recover.js. #}
    <div id="passkey-recover" hidden ng-non-bindable data-uidb64="{{ uidb64 }}">
      <p>{% trans "Create a new passkey on this device to sign in again." %}</p>
      <button type="button" class="btn btn-primary" id="passkey-recover-button">{% trans "Create a new passkey" %}</button>
      <br/><span class="error-msg" id="passkey-recover-error"></span>
      <hr/>
      <p>{% trans "Or set a new password:" %}</p>
    </div>
    <form class="form-horizontal" method="post" action="">{% csrf_token %}
```

and append to the end of the file:

```html

{% block script %}
<script src="{% static 'passkey.js' %}"></script>
<script src="{% static 'passkey_recover.js' %}"></script>
{% endblock %}
```

- [ ] **Step 4: Write the page script**

Create `app/assets/passkey_recover.js`:

```javascript
/* Password-reset confirm page: recover by creating a new passkey. */
(function (window, document) {
  'use strict';
  var P = window.Passkey;
  var box = document.getElementById('passkey-recover');
  if (!box || !P.supported) { return; }
  box.hidden = false;

  var errorEl = document.getElementById('passkey-recover-error');
  var uid = {uidb64: box.dataset.uidb64};

  document.getElementById('passkey-recover-button').addEventListener('click', function () {
    errorEl.textContent = '';
    P.create('/account/recover/passkey/begin/', '/account/recover/passkey/finish/', uid, uid)
      .then(function (data) { window.location.assign(data.redirect); })
      .catch(function (err) { errorEl.textContent = P.errorMessage(err); });
  });
})(window, document);
```

- [ ] **Step 5: Check syntax and run the tests**

Run:
```bash
node --check app/assets/passkey_recover.js
docker compose exec -T web python -m pytest user_data/tests/test_recovery.py -v --no-cov
```
Expected: exit 0; 17 passed.

- [ ] **Step 6: Commit**

```bash
git add app/templates/registration/password_reset_confirm.html app/assets/passkey_recover.js app/user_data/tests/test_recovery.py
git commit -m "$(cat <<'EOF'
feat(recovery): create-a-new-passkey button on the reset confirm page

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---
### Task 22: Thai translations

**Files:**
- Modify: `app/locale/th/LC_MESSAGES/django.po` (append)
- Modify: `app/locale/th/LC_MESSAGES/django.mo` (compiled)
- Test: `app/user_data/tests/test_passkey_i18n.py`

"Created", "Delete", "Password", "Email", "Username", "Unable to log in with provided credentials.", "This account is not active. Please verify your email.", "Verification e-mail sent.", "A user with that username already exists." and "This password reset link is invalid or has expired." already exist in the `.po`; do not add them again (msgfmt rejects duplicates).

- [ ] **Step 1: Write the failing test**

Create `app/user_data/tests/test_passkey_i18n.py`:

```python
import pytest
from django.template.loader import render_to_string
from django.utils import translation

NEW_MSGIDS = [
    'A passkey was added to your E-Tipitaka account',
    'Passkey registration failed.',
    'Re-authentication failed.',
    'Passkey not found.',
    'Enter a name for this passkey.',
    'Your account must keep at least one way to sign in.',
    'Enter a valid username. This value may contain only letters, numbers, and '
    '@/./+/-/_ characters.',
    'Sign in with a passkey',
    'Create account with a passkey',
    'Sign up with a password instead',
    'Sign-in and security',
    'This browser does not support passkeys.',
    'Passkeys',
    'Name',
    'Type',
    'Last used',
    'You have no passkeys yet.',
    'Current password',
    'Add a passkey',
    'Remove password',
    'Never',
    'Synced',
    'This device only',
    'Rename',
    'New name for this passkey',
    'Your account has a password.',
    'Your account has no password. You sign in with a passkey.',
    'Security',
    'The passkey request was cancelled.',
    'Create a new passkey on this device to sign in again.',
    'Create a new passkey',
    'Or set a new password:',
    'Hello %(username)s,',
    'We received a request to recover your E-Tipitaka account.',
    'Open the link below to set a new password or create a new passkey:',
    'If you did not ask for this, you can ignore this e-mail.',
    'A new passkey named "%(passkey_name)s" was added to your E-Tipitaka account.',
    'You can review your passkeys here:',
    'If this was not you, recover your account now and remove the passkey:',
]


@pytest.mark.parametrize('msgid', NEW_MSGIDS)
def test_passkey_string_has_thai_translation(msgid):
    with translation.override('th'):
        assert translation.gettext(msgid) != msgid


def test_passkey_added_email_renders_in_thai():
    with translation.override('th'):
        body = render_to_string('email/passkey_added.txt', {
            'username': 'alice', 'passkey_name': 'Phone',
            'security_url': 'https://x/account/security/', 'reset_url': 'https://x/password_reset/'})
    assert 'สวัสดี alice' in body
    assert '"Phone"' in body
    assert 'https://x/account/security/' in body
```

- [ ] **Step 2: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_i18n.py -v --no-cov`
Expected: FAIL — most parametrized cases fail (untranslated).

- [ ] **Step 3: Append the Thai entries**

Append to `app/locale/th/LC_MESSAGES/django.po`:

```po

msgid "A passkey was added to your E-Tipitaka account"
msgstr "มีการเพิ่มพาสคีย์ในบัญชี E-Tipitaka ของคุณ"

msgid "Passkey registration failed."
msgstr "ลงทะเบียนพาสคีย์ไม่สำเร็จ"

msgid "Re-authentication failed."
msgstr "ยืนยันตัวตนอีกครั้งไม่สำเร็จ"

msgid "Passkey not found."
msgstr "ไม่พบพาสคีย์"

msgid "Enter a name for this passkey."
msgstr "โปรดตั้งชื่อพาสคีย์นี้"

msgid "Your account must keep at least one way to sign in."
msgstr "บัญชีของคุณต้องมีวิธีเข้าสู่ระบบอย่างน้อยหนึ่งวิธี"

msgid ""
"Enter a valid username. This value may contain only letters, numbers, and @/./"
"+/-/_ characters."
msgstr ""
"โปรดกรอกชื่อผู้ใช้ที่ถูกต้อง ชื่อผู้ใช้ประกอบด้วยตัวอักษร ตัวเลข และอักขระ @/./+/-/_ "
"เท่านั้น"

msgid "Sign in with a passkey"
msgstr "เข้าสู่ระบบด้วยพาสคีย์"

msgid "Create account with a passkey"
msgstr "สร้างบัญชีด้วยพาสคีย์"

msgid "Sign up with a password instead"
msgstr "สมัครด้วยรหัสผ่านแทน"

msgid "Sign-in and security"
msgstr "การเข้าสู่ระบบและความปลอดภัย"

msgid "This browser does not support passkeys."
msgstr "เบราว์เซอร์นี้ไม่รองรับพาสคีย์"

msgid "Passkeys"
msgstr "พาสคีย์"

msgid "Name"
msgstr "ชื่อ"

msgid "Type"
msgstr "ประเภท"

msgid "Last used"
msgstr "ใช้ล่าสุด"

msgid "You have no passkeys yet."
msgstr "คุณยังไม่มีพาสคีย์"

msgid "Current password"
msgstr "รหัสผ่านปัจจุบัน"

msgid "Add a passkey"
msgstr "เพิ่มพาสคีย์"

msgid "Remove password"
msgstr "ลบรหัสผ่าน"

msgid "Never"
msgstr "ยังไม่เคยใช้"

msgid "Synced"
msgstr "ซิงค์ข้ามอุปกรณ์"

msgid "This device only"
msgstr "เฉพาะอุปกรณ์นี้"

msgid "Rename"
msgstr "เปลี่ยนชื่อ"

msgid "New name for this passkey"
msgstr "ชื่อใหม่ของพาสคีย์นี้"

msgid "Your account has a password."
msgstr "บัญชีของคุณมีรหัสผ่าน"

msgid "Your account has no password. You sign in with a passkey."
msgstr "บัญชีของคุณไม่มีรหัสผ่าน คุณเข้าสู่ระบบด้วยพาสคีย์"

msgid "Security"
msgstr "ความปลอดภัย"

msgid "The passkey request was cancelled."
msgstr "คำขอพาสคีย์ถูกยกเลิก"

msgid "Create a new passkey on this device to sign in again."
msgstr "สร้างพาสคีย์ใหม่บนอุปกรณ์นี้เพื่อกลับเข้าสู่ระบบ"

msgid "Create a new passkey"
msgstr "สร้างพาสคีย์ใหม่"

msgid "Or set a new password:"
msgstr "หรือตั้งรหัสผ่านใหม่:"

msgid "Hello %(username)s,"
msgstr "สวัสดี %(username)s"

msgid "We received a request to recover your E-Tipitaka account."
msgstr "เราได้รับคำขอกู้คืนบัญชี E-Tipitaka ของคุณ"

msgid "Open the link below to set a new password or create a new passkey:"
msgstr "เปิดลิงก์ด้านล่างเพื่อตั้งรหัสผ่านใหม่หรือสร้างพาสคีย์ใหม่:"

msgid "If you did not ask for this, you can ignore this e-mail."
msgstr "หากคุณไม่ได้ส่งคำขอนี้ โปรดเพิกเฉยต่ออีเมลนี้"

msgid "A new passkey named \"%(passkey_name)s\" was added to your E-Tipitaka account."
msgstr "มีการเพิ่มพาสคีย์ชื่อ \"%(passkey_name)s\" ในบัญชี E-Tipitaka ของคุณ"

msgid "You can review your passkeys here:"
msgstr "คุณตรวจสอบพาสคีย์ของคุณได้ที่:"

msgid "If this was not you, recover your account now and remove the passkey:"
msgstr "หากไม่ใช่คุณ โปรดกู้คืนบัญชีทันทีและลบพาสคีย์นั้น:"
```

- [ ] **Step 4: Compile the catalog on the host**

Run:
```bash
msgfmt --check -o app/locale/th/LC_MESSAGES/django.mo app/locale/th/LC_MESSAGES/django.po
```
Expected: no output, exit 0. A "duplicate message definition" error means a msgid already exists — delete the new copy and re-run.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_passkey_i18n.py user_data/tests/test_i18n.py -v --no-cov`
Expected: all passed (40 new).

- [ ] **Step 6: Commit**

```bash
git add app/locale/th/LC_MESSAGES/django.po app/locale/th/LC_MESSAGES/django.mo app/user_data/tests/test_passkey_i18n.py
git commit -m "$(cat <<'EOF'
feat(passkey): Thai translations for passkey pages, API and emails

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 23: nginx rate-limit zone and deploy health check

**Files:**
- Modify: `nginx/nginx.conf`
- Modify: `deploy.sh`

- [ ] **Step 1: Add the zone**

In `nginx/nginx.conf`, after the `verify_rl` `limit_req_zone` line add:

```nginx
# Passkey ceremonies and browser passkey login are anonymous and each writes a
# challenge row; a legitimate client needs a handful per sign-in.
limit_req_zone $binary_remote_addr zone=passkey_rl:10m rate=30r/m;
```

After the `location = /api/oauth/verify/ { ... }` block add:

```nginx
    # Passkey API, browser passkey login and passkey recovery.
    location ~ ^/(api/passkeys/|login/passkey/|account/recover/passkey/) {
        limit_req zone=passkey_rl burst=10 nodelay;
        error_page 429 = @ratelimited_passkey;
        proxy_pass http://app;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $forwarded_proto;
        proxy_set_header Host $http_host;
        proxy_redirect off;
    }
```

After the `location @ratelimited_verify { ... }` block add:

```nginx
    # passkey_rl refills at 30r/m (one token every 2s).
    location @ratelimited_passkey {
        add_header Retry-After 2 always;
        default_type application/json;
        return 429 '{"error":"rate_limited","retry_after":2}';
    }
```

- [ ] **Step 2: Rebuild nginx and validate**

Run:
```bash
docker compose build nginx && docker compose up -d nginx
docker compose exec -T nginx nginx -t
for i in $(seq 1 15); do curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' -d '{}' http://localhost:1338/api/passkeys/login/begin/; done | sort | uniq -c
```
Expected: `syntax is ok` / `test is successful`; roughly `11 200` and `4 429`. Wait 30 seconds afterwards so later steps are not throttled.

- [ ] **Step 3: Add the deploy check**

In `deploy.sh`, overwrite everything from the line `sleep 5` to the end of the file with:

```sh
sleep 5
if curl -fsS -o /dev/null http://localhost:1338/; then
    echo "[deploy] health check passed"
else
    echo "[deploy] health check FAILED" >&2
    exit 1
fi
if curl -fsS http://localhost:1338/.well-known/apple-app-site-association | grep -q '"webcredentials"'; then
    echo "[deploy] passkey association check passed"
else
    echo "[deploy] passkey association check FAILED" >&2
    exit 1
fi
echo "[deploy] done"
```

- [ ] **Step 4: Verify the script**

Run:
```bash
sh -n deploy.sh
curl -fsS http://localhost:1338/.well-known/apple-app-site-association | grep -q '"webcredentials"' && echo OK
```
Expected: no syntax output; `OK`.

- [ ] **Step 5: Commit**

```bash
git add nginx/nginx.conf deploy.sh
git commit -m "$(cat <<'EOF'
feat(passkey): nginx rate limit for passkey endpoints and deploy AASA check

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 24: Golden harness cases

**Files:**
- Modify: `tests/golden/normalize.py`
- Modify: `tests/golden/test_normalize.py`
- Modify: `tests/golden/endpoints.py`
- Create: `tests/golden/snapshots/{apple_app_site_association,assetlinks_unset,passkey_login_begin,passkey_login_finish_bad_challenge,passkeys_list_anon,passkeys_list_alice}.json` (recorded)
- Modify: `tests/golden/README.md`

Record with **no** `PASSKEY_RP_ID` / `PASSKEY_WEB_ORIGIN` in `docker-compose.override.yml` (CI has none), so `rpId` is the production default.

- [ ] **Step 1: Write the failing normalizer test**

Append to `tests/golden/test_normalize.py`:

```python


def test_webauthn_challenges_are_masked():
    value = {"challenge_id": "abc", "options": {"challenge": "xyz", "rpId": "data.etipitaka.com"}}
    assert normalize_json_value(value) == {
        "challenge_id": "<CHALLENGE>",
        "options": {"challenge": "<CHALLENGE>", "rpId": "data.etipitaka.com"},
    }
```

Run: `tests/golden/.venv/bin/python -m pytest tests/golden/test_normalize.py -v`
Expected: FAIL on the new test.

- [ ] **Step 2: Mask challenges**

In `tests/golden/normalize.py`, inside `normalize_json_value`, replace

```python
            elif key == "pk":
```
with
```python
            elif key in ("challenge", "challenge_id"):
                # WebAuthn challenges are random per request
                out[key] = "<CHALLENGE>"
            elif key == "pk":
```

Run: `tests/golden/.venv/bin/python -m pytest tests/golden/test_normalize.py -v`
Expected: all passed.

- [ ] **Step 3: Let cases send JSON bodies and add the passkey cases**

In `tests/golden/endpoints.py`, replace the `GoldenCase` class with:

```python
class GoldenCase(object):
    def __init__(self, case_id, method, path, token=None, data=None,
                 files=None, allow_redirects=False, json_body=None):
        self.id = case_id
        self.method = method
        self.path = path
        self.token = token
        self.data = data
        self.files = files
        self.allow_redirects = allow_redirects
        self.json_body = json_body

    def execute(self, http, base_url):
        headers = {}
        if self.token:
            headers["Authorization"] = "Token " + self.token
        files = None
        if self.files:
            files = {k: (fn, io.BytesIO(content), ct)
                     for k, (fn, content, ct) in self.files.items()}
        return http.request(
            self.method, base_url + self.path,
            headers=headers, data=self.data, files=files, json=self.json_body,
            allow_redirects=self.allow_redirects, timeout=30,
        )
```

After the `mcp_unauthenticated` case add:

```python

    # --- passkeys (same-stack; old stack lacks these routes) ---
    GoldenCase("apple_app_site_association", "GET", "/.well-known/apple-app-site-association"),
    GoldenCase("assetlinks_unset", "GET", "/.well-known/assetlinks.json"),
    GoldenCase("passkey_login_begin", "POST", "/api/passkeys/login/begin/", json_body={}),
    GoldenCase("passkey_login_finish_bad_challenge", "POST", "/api/passkeys/login/finish/",
               json_body={"challenge_id": "nope", "credential": {}}),
    GoldenCase("passkeys_list_anon", "GET", "/api/passkeys/"),
    GoldenCase("passkeys_list_alice", "GET", "/api/passkeys/", token=ALICE_TOKEN),
```

- [ ] **Step 4: Record the new snapshots**

Run:
```bash
docker compose exec -T web python manage.py seed_golden
tests/golden/.venv/bin/python -m pytest tests/golden/test_golden.py --record --base-url http://localhost:1338 -k "apple_app_site_association or assetlinks_unset or passkey"
```
Expected: 6 skipped ("recorded snapshot for …"). Inspect them:

```bash
cat tests/golden/snapshots/passkey_login_begin.json tests/golden/snapshots/passkeys_list_alice.json
```
Expected: `passkey_login_begin` has `"challenge": "<CHALLENGE>"`, `"challenge_id": "<CHALLENGE>"`, `"rpId": "data.etipitaka.com"`, `"userVerification": "required"`; `passkeys_list_alice` is `{"has_password": true, "passkeys": []}` with status 200.

- [ ] **Step 5: Document the cases**

In `tests/golden/README.md`, after the OAuth / remote-MCP bullet add:

```markdown
- The passkey snapshots (`apple_app_site_association`, `assetlinks_unset`,
  `passkey_login_begin`, `passkey_login_finish_bad_challenge`,
  `passkeys_list_anon`, `passkeys_list_alice`) are same-stack — these routes
  did not exist on the old stack. Random WebAuthn challenge values are masked
  as `<CHALLENGE>`. Record and assert **without** a `PASSKEY_RP_ID` /
  `PASSKEY_WEB_ORIGIN` dev override so `rpId` is the production default.
  `passkey_login_finish_bad_challenge` carries a localized error message.
```

- [ ] **Step 6: Run the whole golden suite**

Run:
```bash
docker compose exec -T web python manage.py seed_golden
tests/golden/.venv/bin/python -m pytest tests/golden -v --base-url http://localhost:1338
```
Expected: all passed (51 = 45 existing + 6 new; if the existing count differs, only the 6 new must be added and nothing else may fail).

- [ ] **Step 7: Commit**

```bash
git add tests/golden/normalize.py tests/golden/test_normalize.py tests/golden/endpoints.py tests/golden/snapshots tests/golden/README.md
git commit -m "$(cat <<'EOF'
test(golden): passkey endpoint snapshots with masked challenges

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 25: End-to-end passkey script

**Files:**
- Create: `tests/passkey_e2e.py`

- [ ] **Step 1: Write the script**

Create `tests/passkey_e2e.py`:

```python
"""End-to-end check of passkeys against a running stack.

Runs inside the web container, so it can use the unit tests' software
authenticator and create and delete its own throwaway accounts:

    docker compose exec -T web python - http://web:8000 < tests/passkey_e2e.py

Flow: password login -> step-up -> link passkey -> passkey token login ->
/rest-auth/user/ -> browser passkey login carrying an OAuth authorize `next`
-> consent page -> passkey step-up -> remove password -> last-passkey guard
-> passkey signup -> login refused until activated -> login.

The authenticator answers for the relying party the server advertises: origin
https://<rpId>, or http://localhost:1338 when a dev override sets rpId to
localhost. Repeated runs within a minute may hit the passkey throttle (429).
"""
import http.cookiejar
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'etipitaka_auth.settings')
import django  # noqa: E402

django.setup()

from django.contrib.auth.models import User  # noqa: E402
from oauth2_provider.models import Application  # noqa: E402

from user_data.tests.soft_authenticator import SoftAuthenticator  # noqa: E402

PASSWORD = 'e2e-Passkey-' + secrets.token_hex(4)
REDIRECT = 'https://app.example/cb'
# RFC 7636 appendix B example challenge; the flow never exchanges the code.
PKCE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, base):
        self.base = base.rstrip('/')
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())
        self.token = None

    def call(self, method, path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header('Accept', 'application/json')
        if body is not None:
            request.add_header('Content-Type', 'application/json')
        if self.token:
            request.add_header('Authorization', 'Token ' + self.token)
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with self.opener.open(request, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()

    def json(self, method, path, body=None, expect=200, headers=None):
        status, _headers, raw = self.call(method, path, body, headers)
        assert status == expect, '%s %s -> %s %s' % (method, path, status, raw[:300])
        return json.loads(raw) if raw else {}

    def cookie(self, name):
        return next(c.value for c in self.jar if c.name == name)


def origin_for(rp_id):
    return 'http://localhost:1338' if rp_id == 'localhost' else 'https://' + rp_id


def register(client, authenticator, begin_path, finish_path, begin_body):
    begin = client.json('POST', begin_path, begin_body)
    credential = authenticator.register(begin['options'],
                                        origin=origin_for(begin['options']['rp']['id']))
    return client.json('POST', finish_path, {'challenge_id': begin['challenge_id'],
                                             'credential': credential, 'name': 'e2e'},
                       expect=201)


def assertion(client, authenticator):
    begin = client.json('POST', '/api/passkeys/login/begin/', {})
    return {'challenge_id': begin['challenge_id'],
            'credential': authenticator.assert_(begin['options'],
                                                origin=origin_for(begin['options']['rpId']))}


def run(base, username, app, signup_name):
    authenticator = SoftAuthenticator()

    api = Client(base)
    api.token = api.json('POST', '/rest-auth/login/',
                         {'username': username, 'password': PASSWORD})['key']
    api.json('POST', '/api/passkeys/register/begin/', {'password': 'wrong'}, expect=400)
    created = register(api, authenticator, '/api/passkeys/register/begin/',
                       '/api/passkeys/register/finish/', {'password': PASSWORD})
    print('linked passkey after password step-up:', created['name'])

    anon = Client(base)
    key = anon.json('POST', '/api/passkeys/login/finish/', assertion(anon, authenticator))['key']
    assert key == api.token, 'passkey login must return the account token'
    anon.token = key
    assert anon.json('GET', '/rest-auth/user/')['username'] == username
    print('passkey token login: OK')

    web = Client(base)
    query = urllib.parse.urlencode({
        'response_type': 'code', 'client_id': app.client_id, 'redirect_uri': REDIRECT,
        'scope': 'etipitaka:read', 'code_challenge': PKCE_CHALLENGE,
        'code_challenge_method': 'S256', 'state': 'e2e'})
    status, headers, _raw = web.call('GET', '/o/authorize/?' + query)
    assert status == 302, status
    next_url = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)['next'][0]
    web.call('GET', '/login/')
    body = dict(assertion(web, authenticator), next=next_url)
    redirect = web.json('POST', '/login/passkey/', body,
                        headers={'X-CSRFToken': web.cookie('csrftoken')})['redirect']
    assert redirect == next_url, redirect
    status, _headers, page = web.call('GET', redirect)
    assert status == 200 and b'name="allow"' in page, status
    print('browser passkey login -> OAuth consent page: OK')

    api.json('POST', '/api/passkeys/register/begin/', {'step_up': assertion(anon, authenticator)})
    print('passkey step-up: OK')

    assert api.json('POST', '/api/passkeys/password/remove/',
                    {'password': PASSWORD}) == {'has_password': False}
    only = api.json('GET', '/api/passkeys/')['passkeys'][0]['id']
    api.json('DELETE', '/api/passkeys/%d/' % only, expect=409)
    print('password removed; last passkey guarded: OK')

    newcomer = SoftAuthenticator()
    guest = Client(base)
    register(guest, newcomer, '/api/passkeys/signup/begin/', '/api/passkeys/signup/finish/',
             {'username': signup_name, 'email': signup_name + '@example.com'})
    guest.json('POST', '/api/passkeys/login/finish/', assertion(guest, newcomer), expect=400)
    User.objects.filter(username=signup_name).update(is_active=True)
    assert guest.json('POST', '/api/passkeys/login/finish/', assertion(guest, newcomer))['key']
    print('passkey signup -> verified -> login: OK')


def main(base):
    suffix = secrets.token_hex(4)
    username, signup_name = 'e2e_pk_' + suffix, 'e2e_su_' + suffix
    User.objects.create_user(username, username + '@example.com', PASSWORD)
    app = Application.objects.create(
        name='passkey-e2e', client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris=REDIRECT, client_secret='', hash_client_secret=False)
    try:
        run(base, username, app, signup_name)
    finally:
        User.objects.filter(username__in=[username, signup_name]).delete()
        app.delete()
    print('PASSKEY E2E OK')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'http://web:8000')
```

- [ ] **Step 2: Run it**

Run:
```bash
docker compose exec -T web python - http://web:8000 < tests/passkey_e2e.py
```
Expected, ending with:
```
linked passkey after password step-up: e2e
passkey token login: OK
browser passkey login -> OAuth consent page: OK
passkey step-up: OK
password removed; last passkey guarded: OK
passkey signup -> verified -> login: OK
PASSKEY E2E OK
```
If a step fails, the assertion message names the request and response; fix the code, not the script.

- [ ] **Step 3: Commit**

```bash
git add tests/passkey_e2e.py
git commit -m "$(cat <<'EOF'
test(passkey): end-to-end script covering link, login, OAuth next and signup

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 26: Client integration guide and spec sync

**Files:**
- Create: `docs/passkeys-client-integration.md`
- Modify: `docs/superpowers/specs/2026-09-14-passkey-login-design.md`

- [ ] **Step 1: Write the guide**

Create `docs/passkeys-client-integration.md`:

````markdown
# Passkeys — client integration and operator guide

Server side of passkey sign-in for E-Tipitaka. Design:
`docs/superpowers/specs/2026-09-14-passkey-login-design.md`.

- **Relying party ID:** `data.etipitaka.com`
- **Web origin:** `https://data.etipitaka.com`
- **Discoverable credentials, user verification required, attestation `none`.**

## Ceremony shape

Every ceremony is two POSTs with JSON bodies.

1. **begin** → `200 {"challenge_id": "...", "options": {...}}`. `options` is
   the standard `PublicKeyCredentialCreationOptionsJSON` or
   `PublicKeyCredentialRequestOptionsJSON`.
2. **finish** ← `{"challenge_id": "...", "credential": {...}}`. `credential`
   is the standard `RegistrationResponseJSON` / `AuthenticationResponseJSON`
   (base64url fields, `response.transports` on registration,
   `response.userHandle` on login).

A challenge is single use and expires after 5 minutes. A reused, expired or
wrong-ceremony challenge returns 400; start again with begin.

## Endpoints

Authentication column: **none** = anonymous; **account** = `Authorization:
Token <key>` (apps) or the web session + `X-CSRFToken`. OAuth bearer tokens are
**rejected** on account endpoints.

| Endpoint | Auth | Body | Success | Errors |
|---|---|---|---|---|
| `POST /api/passkeys/login/begin/` | none | `{}` | 200 ceremony | 429 |
| `POST /api/passkeys/login/finish/` | none | ceremony | 200 `{"key": "<token>"}` (same as `/rest-auth/login/`) | 400 `{"non_field_errors": [msg]}` |
| `POST /api/passkeys/signup/begin/` | none | `{"username", "email"}` | 200 ceremony | 400 field errors |
| `POST /api/passkeys/signup/finish/` | none | ceremony + optional `"name"` | 201 `{"detail"}` — account inactive until the emailed link is opened | 400 |
| `POST /api/passkeys/register/begin/` | account | `{"password"}` **or** `{"step_up": {"challenge_id", "credential"}}` | 200 ceremony | 400 re-authentication failed, 401 |
| `POST /api/passkeys/register/finish/` | account | ceremony + optional `"name"` | 201 passkey | 400, 401 |
| `GET /api/passkeys/` | account | — | 200 `{"has_password", "passkeys": [passkey]}` | 401 |
| `PATCH /api/passkeys/<id>/` | account | `{"name"}` | 200 passkey | 400, 404 |
| `DELETE /api/passkeys/<id>/` | account | — | 204 | 404, 409 last way to sign in |
| `POST /api/passkeys/password/remove/` | account | `{"password"}` | 200 `{"has_password": false}` | 400 wrong password, 409 |

Passkey object: `{"id", "name", "authenticator", "backed_up", "created_at", "last_used_at"}`.

Rate limits: nginx 30 requests/min per IP (burst 10) on `/api/passkeys/`,
plus 20/min per user or IP in Django. Honour `Retry-After` on 429.

## Flows

**Sign in:** `login/begin` → system passkey sheet → `login/finish` → store the
token exactly as after password login.

**Link a passkey (existing users):** ask for the current password →
`register/begin {"password"}` → system sheet → `register/finish`. A user with
no password proves themselves with a passkey first: `login/begin` → sheet →
send `{"step_up": {challenge_id, credential}}` to `register/begin`. The account
owner receives a "new passkey added" email.

**Sign up:** `signup/begin {"username", "email"}` → sheet → `signup/finish` →
tell the user to open the verification email. Until then `login/finish`
returns 400 "This account is not active…".

**Lost passkey / forgot password:** open `https://data.etipitaka.com/password_reset/`
in `ASWebAuthenticationSession` (iOS) or a Custom Tab (Android). The emailed
link lets the user create a new passkey (saved under the same RP ID, so the app
can use it immediately) or set a password. Recovery signs out every device:
the app's token stops working and it must sign in again.

## iOS

- Entitlement **Associated Domains**: `webcredentials:data.etipitaka.com`.
- The server publishes `https://data.etipitaka.com/.well-known/apple-app-site-association`
  listing `A6DJDJ7527.com.watnapp.E-Tipitaka-Plus`. Apple fetches it through
  its CDN; after a deploy check
  `https://app-site-association.cdn-apple.com/a/v1/data.etipitaka.com`.
- Use `ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "data.etipitaka.com")`:
  `createCredentialRegistrationRequest(challenge:name:userID:)` with the
  decoded `options.challenge` / `options.user.id`, and
  `createCredentialAssertionRequest(challenge:)` for login. Set
  `userVerificationPreference = .required`. For login autofill use
  `performAutoFillAssistedRequests()`.
- Build `credential` JSON from `ASAuthorizationPlatformPublicKeyCredentialRegistration`
  (`rawClientDataJSON`, `rawAttestationObject`, `credentialID`) and
  `…Assertion` (`rawClientDataJSON`, `rawAuthenticatorData`, `signature`,
  `userID`, `credentialID`), base64url-encoding each field. iOS reports origin
  `https://data.etipitaka.com`.

## Android

- The operator sets `PASSKEY_ANDROID_PACKAGE` and `PASSKEY_ANDROID_CERT_SHA256`
  (see below); until then `/.well-known/assetlinks.json` is 404 and Android
  assertions are rejected.
- Use Credential Manager: `CreatePublicKeyCredentialRequest(requestJson)` and
  `GetPublicKeyCredentialOption(requestJson)`, passing `options` as JSON. The
  returned `registrationResponseJson` / `authenticationResponseJson` is sent as
  `credential` unchanged.
- Android reports origin `android:apk-key-hash:<base64url(SHA-256 of signing cert)>`;
  the server derives it from `PASSKEY_ANDROID_CERT_SHA256`.

## Testing native clients

Native passkeys need the association files over real HTTPS; `localhost` does
not work. Test against production, or expose a dev stack through an HTTPS
tunnel and set `PASSKEY_RP_ID` / `PASSKEY_WEB_ORIGIN` to the tunnel host.

## Operator settings

Set in each environment's **gitignored** `docker-compose.override.yml`
(`services.web.environment`), never the tracked `.env`:

| Variable | Default | Example |
|---|---|---|
| `PASSKEY_RP_ID` | host of `OAUTH_ISSUER_URL` | dev: `localhost` |
| `PASSKEY_WEB_ORIGIN` | `OAUTH_ISSUER_URL` | dev: `http://localhost:1338` |
| `PASSKEY_IOS_APP_IDS` | `A6DJDJ7527.com.watnapp.E-Tipitaka-Plus` | comma list |
| `PASSKEY_ANDROID_PACKAGE` | empty | `com.watnapp.etipitaka` |
| `PASSKEY_ANDROID_CERT_SHA256` | empty | `AB:CD:…` (comma list, colon-hex) |

Passkeys are bound to the RP ID: passkeys created against `localhost` never
work on production. Remove the dev override before running the golden harness.
````

- [ ] **Step 2: Sync the spec with the plan's refinements**

In `docs/superpowers/specs/2026-09-14-passkey-login-design.md`:

1. In the Component 2 settings table, replace the `PASSKEY_EXPECTED_ORIGINS` row's first cell text `` `PASSKEY_EXPECTED_ORIGINS` `` with `` `passkey_config.expected_origins()` ``.
2. In Component 1, replace `built-in AAGUID map (iCloud Keychain, Google Password Manager, Windows Hello,` with `built-in AAGUID map (Apple Passwords, Google Password Manager, Windows Hello,`.
3. In the Component 4 table, change the assetlinks row's Errors cell to `404 JSON when Android settings empty`.
4. Replace the whole `## Deliverables` section body with:

```markdown
- `app/requirements.txt` — `webauthn==3.0.0`.
- `app/user_data/models.py`, `migrations/0005_passkeys.py`.
- `app/user_data/passkey_config.py`, `passkey_challenges.py`,
  `passkey_service.py`, `passkey_manage.py`, `account_tokens.py`,
  `passkey_views.py`, `passkey_web_views.py`, `wellknown_views.py`,
  `recovery.py`; `serializers.py` (`AccountIdentitySerializer`).
- `app/etipitaka_auth/settings.py`, `urls.py`.
- Templates: `account_security.html`, `login.html`, `forms/login_form.html`,
  `signup.html`, `registration/password_reset_confirm.html`,
  `registration/password_reset_email.txt`, `email/passkey_added.txt`,
  `base.html`.
- `app/assets/passkey.js`, `passkey_login.js`, `passkey_signup.js`,
  `account_security.js`, `passkey_recover.js`.
- `app/locale/th/LC_MESSAGES/django.po` / `.mo`.
- `nginx/nginx.conf`, `deploy.sh`.
- Unit tests, golden snapshots + README note, `tests/passkey_e2e.py`.
- `docs/passkeys-client-integration.md`.
- Plan: `docs/superpowers/plans/2026-09-14-passkey-login.md`.
```

5. In the Error handling table, replace the two lockout rows' response text with `409 "Your account must keep at least one way to sign in."`.

- [ ] **Step 3: Commit**

```bash
git add docs/passkeys-client-integration.md docs/superpowers/specs/2026-09-14-passkey-login-design.md
git commit -m "$(cat <<'EOF'
docs(passkey): client integration guide; sync spec with implementation

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 27: Full verification and manual browser check

**Files:** none changed unless a check fails.

- [ ] **Step 1: Full unit suite with the coverage gate**

Run: `docker compose exec -T web python -m pytest`
Expected: all passed; `Required test coverage of 90% reached`.

- [ ] **Step 2: Golden harness and both e2e scripts**

Run:
```bash
docker compose exec -T web python manage.py seed_golden
tests/golden/.venv/bin/python -m pytest tests/golden -v --base-url http://localhost:1338
mcp_server/.venv/bin/python tests/oauth_e2e.py http://localhost:1338
docker compose exec -T web python - http://web:8000 < tests/passkey_e2e.py
```
Expected: golden all passed; OAuth e2e prints its success lines (12 tools, whoami OK); `PASSKEY E2E OK`. (The OAuth e2e registers a DCR client, limited to 6/min.)

- [ ] **Step 3: Manual browser check (real authenticator)**

Add to the gitignored `docker-compose.override.yml` under `services.web.environment`:

```yaml
      PASSKEY_RP_ID: localhost
      PASSKEY_WEB_ORIGIN: http://localhost:1338
```

Run:
```bash
docker compose up -d web
docker compose exec -T web python manage.py collectstatic --noinput
```

In Chrome or Safari on this Mac, at `http://localhost:1338`:
1. `/signup/` → passkey form shows → create account with a passkey → lands on `/signup/validate/`; `docker compose logs web | grep confirm-email` shows the link; open it.
2. `/login/` → focus the username field: the browser offers the passkey (autofill) → signs in. Log out; sign in again with the "Sign in with a passkey" button.
3. `/account/security/` → passkey listed; rename; for a password account add a passkey (password prompt), then "Remove password"; deleting the only passkey shows the 409 message.
4. Log out → `/password_reset/` with the account email → link from `docker compose logs web` → "Create a new passkey" → lands on `/account/security/` signed in.
5. Switch language to ไทย and confirm the passkey texts are Thai.

- [ ] **Step 4: Restore the default relying party**

Remove the two `PASSKEY_*` lines from `docker-compose.override.yml`, then:
```bash
docker compose up -d web
curl -s -X POST -H 'Content-Type: application/json' -d '{}' http://localhost:1338/api/passkeys/login/begin/ | grep -o '"rpId":"[^"]*"'
```
Expected: `"rpId":"data.etipitaka.com"`.

- [ ] **Step 5: Report**

Summarise results (test counts, coverage, golden, both e2e runs, manual check notes). Do not merge, push or deploy without the user's explicit go-ahead; use superpowers:finishing-a-development-branch when they ask.
