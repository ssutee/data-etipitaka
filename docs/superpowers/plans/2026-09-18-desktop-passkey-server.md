# Desktop Passkey Pairing (server) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the E-Tipitaka desktop app sign a user in with a passkey by delegating the ceremony to the system browser and handing the resulting DRF token back over a device-pairing handshake.

**Architecture:** A new `DesktopPairing` row holds one handshake. The desktop app calls `POST /api/passkeys/desktop/begin/` for a secret `device_code` plus a human-readable `user_code`, opens `/desktop/?code=…` in the browser, and polls `POST /api/passkeys/desktop/poll/` until the user confirms the code on that page. Confirmation binds the row to `request.user`; the next poll mints the token and deletes the row. The passkey ceremony itself is the web login that already ships — nothing in `passkey_service.py` or `passkey_login.js` changes.

**Tech Stack:** Django 5.2 / DRF 3.16, PostgreSQL, pytest-django (coverage gate 90 %, `app/pytest.ini`), golden HTTP harness (`tests/golden`), nginx 1.27, Django i18n (Thai).

**Spec:** `E-Tipitaka-PC:docs/superpowers/specs/2026-09-18-desktop-passkey-design.md`

---

## Conventions (read before Task 1)

- **Unit tests run in the container:** `docker compose exec -T web python -m pytest`. For one file while iterating, disable the coverage gate: `docker compose exec -T web python -m pytest user_data/tests/test_x.py -q -o addopts=""`. The container's working directory is the Django project root, so test paths start at `user_data/`.
- If `python -m pytest --version` fails, the prod image lacks pytest — install once:
  `docker compose exec -u root -T -e PIP_DEFAULT_TIMEOUT=300 web pip install --retries 20 -r requirements-dev.txt`
- **Style to copy:** `app/user_data/passkey_challenges.py` for the service module (purge-on-create, `transaction.atomic(durable=True)`, delete-before-verify), `app/user_data/passkey_views.py` for DRF views (`_body()` gate, `_bad_request()`, `PasskeyRateThrottle`), `app/user_data/passkey_web_views.py` for the browser page (plain Django view, CSRF in force).
- **Never** add OAuth bearer auth to these endpoints.
- Thai is the default language and there is no `Accept-Language` negotiation, so every user-facing string goes through `gettext` and gets a Thai translation in Task 10.

## File Structure

| File | Responsibility |
|---|---|
| `app/user_data/models.py` (modify) | `DesktopPairing` row |
| `app/user_data/migrations/00XX_desktoppairing.py` (create) | schema |
| `app/user_data/desktop_pairing.py` (create) | all pairing logic: code generation, create, approve/deny, redeem |
| `app/user_data/passkey_views.py` (modify) | `desktop_begin`, `desktop_poll` DRF views |
| `app/user_data/passkey_web_views.py` (modify) | `desktop_confirm`, `desktop_approve` browser views |
| `app/templates/desktop_confirm.html` (create) | the confirm page |
| `app/etipitaka_auth/urls.py` (modify) | four routes |
| `app/etipitaka_auth/settings.py` (modify) | `PASSKEY_DESKTOP_TTL` |
| `app/user_data/tests/test_desktop_pairing.py` (create) | service unit tests |
| `app/user_data/tests/test_desktop_views.py` (create) | API + page tests |
| `nginx/nginx.conf` (modify) | rate-limit zone |
| `tests/golden/` (modify) | snapshots |
| `tests/passkey_e2e.py` (modify) | end-to-end leg |
| `docs/passkeys-client-integration.md` (modify) | client contract |

Pairing logic lives in one module rather than being split across views, because `create`/`approve`/`redeem` share the code-normalisation and expiry rules and must stay consistent.

---

### Task 1: `DesktopPairing` model

**Files:**
- Modify: `app/user_data/models.py`
- Modify: `app/etipitaka_auth/settings.py`
- Test: `app/user_data/tests/test_desktop_pairing.py` (create)

- [ ] **Step 1: Add the TTL setting**

In `app/etipitaka_auth/settings.py`, directly after `PASSKEY_CHALLENGE_TTL = 300  # seconds`:

```python
# Desktop pairing handshakes live longer than a WebAuthn challenge: the window
# has to cover opening a browser, signing in to the website if there's no
# session yet, and then confirming the code.
PASSKEY_DESKTOP_TTL = 600  # seconds
```

- [ ] **Step 2: Write the failing test**

Create `app/user_data/tests/test_desktop_pairing.py`:

```python
import pytest
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.utils import timezone

from user_data.models import DesktopPairing


@pytest.mark.django_db
def test_pairing_defaults_to_pending():
    row = DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code='K7QP4M2X',
        expires_at=timezone.now())
    assert row.status == DesktopPairing.PENDING
    assert row.user is None


@pytest.mark.django_db
def test_user_code_is_unique():
    # IntegrityError, not a bare Exception, and inside a savepoint: these run
    # against real Postgres in CI, where an IntegrityError outside
    # transaction.atomic() aborts the enclosing transaction. Matches
    # test_passkey_models.py's own unique-constraint tests.
    DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code='K7QP4M2X',
        expires_at=timezone.now())
    with pytest.raises(IntegrityError), transaction.atomic():
        DesktopPairing.objects.create(
            device_code_hash='b' * 64, user_code='K7QP4M2X',
            expires_at=timezone.now())


@pytest.mark.django_db
def test_deleting_the_user_deletes_the_pairing():
    user = User.objects.create_user('alice', password='x')
    DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code='K7QP4M2X',
        user=user, expires_at=timezone.now())
    user.delete()
    assert DesktopPairing.objects.count() == 0
```

- [ ] **Step 3: Run it to confirm it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_pairing.py -q -o addopts=""`
Expected: FAIL — `ImportError: cannot import name 'DesktopPairing'`

- [ ] **Step 4: Add the model**

Append to `app/user_data/models.py`:

```python
class DesktopPairing(models.Model):
    """One desktop sign-in handshake (see user_data/desktop_pairing.py).

    The desktop app holds the device code; only its SHA-256 is stored here, so
    reading this table never yields a code that could be polled for a token --
    the same reasoning as DRF tokens not being reversible from a session.

    user_code is stored canonically (uppercase, no separator); the dash in
    K7QP-4M2X is presentation only.
    """
    PENDING, APPROVED, DENIED = 'pending', 'approved', 'denied'
    STATUSES = [(PENDING, PENDING), (APPROVED, APPROVED), (DENIED, DENIED)]

    device_code_hash = models.CharField(primary_key=True, max_length=64)
    user_code = models.CharField(max_length=8, unique=True)
    status = models.CharField(max_length=8, choices=STATUSES, default=PENDING)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
```

- [ ] **Step 5: Generate the migration**

Run: `docker compose exec -T web python manage.py makemigrations user_data`
Expected: `Create model DesktopPairing`, a new file under `app/user_data/migrations/`.

- [ ] **Step 6: Run the tests to confirm they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_pairing.py -q -o addopts=""`
Expected: 3 passed

- [ ] **Step 7: Commit**

```bash
git add app/user_data/models.py app/user_data/migrations app/etipitaka_auth/settings.py app/user_data/tests/test_desktop_pairing.py
git commit -m "feat(desktop): DesktopPairing model and TTL setting"
```

---

### Task 2: User code generation

**Files:**
- Create: `app/user_data/desktop_pairing.py`
- Test: `app/user_data/tests/test_desktop_pairing.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_desktop_pairing.py`:

```python
from user_data import desktop_pairing


def test_new_user_code_shape():
    code = desktop_pairing.new_user_code()
    assert len(code) == 8
    assert set(code) <= set(desktop_pairing.CODE_ALPHABET)


def test_alphabet_excludes_ambiguous_characters():
    assert not (set('01OI') & set(desktop_pairing.CODE_ALPHABET))


def test_format_and_normalise_round_trip():
    assert desktop_pairing.format_user_code('K7QP4M2X') == 'K7QP-4M2X'
    assert desktop_pairing.normalise_user_code('k7qp-4m2x') == 'K7QP4M2X'
    assert desktop_pairing.normalise_user_code(' K7QP 4M2X ') == 'K7QP4M2X'


def test_normalise_rejects_rubbish():
    assert desktop_pairing.normalise_user_code('') is None
    assert desktop_pairing.normalise_user_code('!!!!') is None
    assert desktop_pairing.normalise_user_code('K7QP4M2') is None      # too short
    assert desktop_pairing.normalise_user_code('K7QP4M2XY') is None    # too long
    assert desktop_pairing.normalise_user_code(None) is None
    assert desktop_pairing.normalise_user_code(123) is None
    # Correct length, disallowed character -- without these the alphabet
    # branch never executes, because every case above trips the length check
    # first and `or` short-circuits.
    assert desktop_pairing.normalise_user_code('K7QP4M2O') is None     # O not in alphabet
    assert desktop_pairing.normalise_user_code('K7QP4M2L') is None     # L not in alphabet


def test_new_user_code_varies():
    # Guards against a regression that draws one character and repeats it:
    # that keeps the length and alphabet correct but destroys the entropy.
    codes = {desktop_pairing.new_user_code() for _ in range(20)}
    assert len(codes) > 1
    assert any(len(set(code)) > 1 for code in codes)


def test_normalise_strips_exotic_separators():
    assert desktop_pairing.normalise_user_code('K7QP 4M2X') == 'K7QP4M2X'   # NBSP
    assert desktop_pairing.normalise_user_code('K7QP　4M2X') == 'K7QP4M2X'   # full-width
    assert desktop_pairing.normalise_user_code('K7QP\t4M2X\n') == 'K7QP4M2X'
    assert desktop_pairing.normalise_user_code('K7QP–4M2X') == 'K7QP4M2X'   # en dash
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_pairing.py -q -o addopts=""`
Expected: FAIL — `ModuleNotFoundError: No module named 'user_data.desktop_pairing'`

- [ ] **Step 3: Create the module with the code helpers**

Create `app/user_data/desktop_pairing.py`:

```python
"""Desktop sign-in pairing handshakes.

A wxPython process cannot produce a WebAuthn credential this server will
accept -- the only allowed origin is https://data.etipitaka.com and origins are
minted by the browser or the OS. So the desktop app delegates the ceremony to
the system browser and collects the resulting token here: begin() issues a
secret device code plus a human-readable user code, the browser confirms the
user code against what the app is displaying, and redeem() hands over the
token.

The device code is the app's secret and is never displayed or stored in the
clear; only its SHA-256 goes in the database.
"""
import hashlib
import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import DesktopPairing

log = logging.getLogger(__name__)

# Crockford-style: no 0/1/I/L/O/U, so a code read off a screen and typed (or
# read aloud) cannot be ambiguous.
CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTVWXYZ'
CODE_LENGTH = 8


class PairingError(Exception):
    """Unknown, expired or already-redeemed pairing."""


def new_user_code():
    return ''.join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def format_user_code(code):
    """Canonical code -> the form shown to a human: K7QP4M2X -> K7QP-4M2X."""
    if len(code) != CODE_LENGTH:
        raise ValueError('expected a %d-character code' % CODE_LENGTH)
    half = CODE_LENGTH // 2
    return code[:half] + '-' + code[half:]


def normalise_user_code(raw):
    """Anything a user or URL supplied -> canonical code, or None if invalid.

    Keeps only alphanumerics, so every separator a code can pick up on its way
    through a browser, a chat app or a PDF -- ASCII and non-breaking spaces,
    tabs, newlines, and hyphens autocorrected into en/em dashes -- is dropped
    rather than rejected.
    """
    if not isinstance(raw, str):
        return None
    code = ''.join(ch for ch in raw if ch.isalnum()).upper()
    if len(code) != CODE_LENGTH or not set(code) <= set(CODE_ALPHABET):
        return None
    return code


def _hash(device_code):
    return hashlib.sha256(device_code.encode()).hexdigest()
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_pairing.py -q -o addopts=""`
Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add app/user_data/desktop_pairing.py app/user_data/tests/test_desktop_pairing.py
git commit -m "feat(desktop): user code alphabet, formatting and normalisation"
```

---

### Task 3: `begin()` — issue a pairing

**Files:**
- Modify: `app/user_data/desktop_pairing.py`
- Test: `app/user_data/tests/test_desktop_pairing.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_desktop_pairing.py`:

```python
from datetime import timedelta
from unittest.mock import patch


@pytest.mark.django_db
def test_begin_returns_a_device_code_and_stores_only_its_hash():
    device_code, row = desktop_pairing.begin()
    assert len(device_code) >= 40
    assert row.device_code_hash == desktop_pairing._hash(device_code)
    assert DesktopPairing.objects.filter(device_code_hash=row.device_code_hash).exists()
    # The plaintext code must appear nowhere in the table.
    assert not DesktopPairing.objects.filter(user_code=device_code).exists()


@pytest.mark.django_db
def test_begin_sets_expiry_from_settings(settings):
    # A non-default TTL on purpose: with the production value (600) this test
    # would pass even if begin() ignored the setting and hardcoded it.
    settings.PASSKEY_DESKTOP_TTL = 123
    before = timezone.now()
    _code, row = desktop_pairing.begin()
    assert row.expires_at >= before + timedelta(seconds=122)
    assert row.expires_at <= timezone.now() + timedelta(seconds=124)


@pytest.mark.django_db
def test_begin_purges_expired_rows():
    DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code='AAAAAAAA',
        expires_at=timezone.now() - timedelta(seconds=1))
    desktop_pairing.begin()
    assert not DesktopPairing.objects.filter(device_code_hash='a' * 64).exists()


@pytest.mark.django_db
def test_begin_retries_on_user_code_collision():
    taken = 'K7QP4M2X'
    DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code=taken,
        expires_at=timezone.now() + timedelta(seconds=600))
    with patch.object(desktop_pairing, 'new_user_code',
                      side_effect=[taken, 'ZZZZ2222']):
        _code, row = desktop_pairing.begin()
    assert row.user_code == 'ZZZZ2222'


@pytest.mark.django_db
def test_begin_raises_when_every_code_collides():
    # return_value, not a fixed-length side_effect list, so this stays correct
    # if _MAX_CODE_ATTEMPTS is ever retuned.
    taken = 'K7QP4M2X'
    DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code=taken,
        expires_at=timezone.now() + timedelta(seconds=600))
    with patch.object(desktop_pairing, 'new_user_code', return_value=taken):
        with pytest.raises(desktop_pairing.PairingError):
            desktop_pairing.begin()
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_pairing.py -q -o addopts=""`
Expected: FAIL — `AttributeError: module 'user_data.desktop_pairing' has no attribute 'begin'`

- [ ] **Step 3: Implement `begin()`**

Append to `app/user_data/desktop_pairing.py`:

```python
_MAX_CODE_ATTEMPTS = 5


def begin():
    """Issue a pairing. Returns (device_code, row); only the hash is stored.

    Expired rows are purged here, the same way passkey_challenges.create()
    purges its own -- there is no separate sweeper process.
    """
    now = timezone.now()
    DesktopPairing.objects.filter(expires_at__lte=now).delete()
    device_code = secrets.token_urlsafe(32)
    expires_at = now + timedelta(seconds=settings.PASSKEY_DESKTOP_TTL)
    for _attempt in range(_MAX_CODE_ATTEMPTS):
        try:
            with transaction.atomic():
                row = DesktopPairing.objects.create(
                    device_code_hash=_hash(device_code),
                    user_code=new_user_code(),
                    expires_at=expires_at)
        except IntegrityError:
            continue  # user_code collided with a live row; draw another
        return device_code, row
    # Five straight collisions in a ~39-bit space is not bad luck. Either the
    # live-row count has grown far beyond anything this table should hold, or
    # the device code itself collided on the primary key -- which would mean a
    # broken entropy source. Both need a human, so say so loudly.
    log.error('desktop pairing: exhausted %d user code attempts', _MAX_CODE_ATTEMPTS)
    raise PairingError('exhausted %d user code attempts' % _MAX_CODE_ATTEMPTS)
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_pairing.py -q -o addopts=""`
Expected: 11 passed

- [ ] **Step 5: Commit**

```bash
git add app/user_data/desktop_pairing.py app/user_data/tests/test_desktop_pairing.py
git commit -m "feat(desktop): issue pairings with collision retry and expiry purge"
```

---

### Task 4: `find_pending()`, `approve()`, `deny()`

**Files:**
- Modify: `app/user_data/desktop_pairing.py`
- Test: `app/user_data/tests/test_desktop_pairing.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_desktop_pairing.py`:

```python
@pytest.mark.django_db
def test_find_pending_by_user_code():
    _code, row = desktop_pairing.begin()
    found = desktop_pairing.find_pending(desktop_pairing.format_user_code(row.user_code))
    assert found.device_code_hash == row.device_code_hash


@pytest.mark.django_db
def test_find_pending_rejects_unknown_expired_and_decided():
    assert desktop_pairing.find_pending('K7QP-4M2X') is None
    assert desktop_pairing.find_pending('not a code') is None

    _code, expired = desktop_pairing.begin()
    DesktopPairing.objects.filter(pk=expired.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1))
    assert desktop_pairing.find_pending(expired.user_code) is None

    _code, decided = desktop_pairing.begin()
    user = User.objects.create_user('alice', password='x')
    desktop_pairing.approve(decided, user)
    assert desktop_pairing.find_pending(decided.user_code) is None


@pytest.mark.django_db
def test_approve_binds_the_user():
    _code, row = desktop_pairing.begin()
    user = User.objects.create_user('alice', password='x')
    desktop_pairing.approve(row, user)
    row.refresh_from_db()
    assert row.status == DesktopPairing.APPROVED
    assert row.user == user


@pytest.mark.django_db
def test_deny_marks_denied_without_a_user():
    _code, row = desktop_pairing.begin()
    desktop_pairing.deny(row)
    row.refresh_from_db()
    assert row.status == DesktopPairing.DENIED
    assert row.user is None


@pytest.mark.django_db
def test_find_pending_excludes_a_denied_pairing():
    # The approved case is covered above; this is the other half of the
    # status=PENDING filter, and "user pressed No, is the code live again?"
    # is exactly the question worth pinning down.
    _code, row = desktop_pairing.begin()
    desktop_pairing.deny(row)
    assert desktop_pairing.find_pending(row.user_code) is None


@pytest.mark.django_db
def test_find_pending_accepts_the_code_as_a_url_would_carry_it():
    _code, row = desktop_pairing.begin()
    lowered = desktop_pairing.format_user_code(row.user_code).lower()
    found = desktop_pairing.find_pending(lowered)
    assert found is not None
    assert found.device_code_hash == row.device_code_hash


@pytest.mark.django_db
def test_deciding_twice_does_not_flip_the_status():
    _code, row = desktop_pairing.begin()
    user = User.objects.create_user('alice', password='x')
    assert desktop_pairing.deny(row) is True
    assert desktop_pairing.approve(row, user) is False
    row.refresh_from_db()
    assert row.status == DesktopPairing.DENIED
    assert row.user is None


@pytest.mark.django_db
def test_deciding_a_vanished_pairing_reports_false():
    # What a concurrent redeem() deleting the row looks like from here: no
    # DatabaseError, just False.
    _code, row = desktop_pairing.begin()
    user = User.objects.create_user('alice', password='x')
    DesktopPairing.objects.filter(pk=row.pk).delete()
    assert desktop_pairing.approve(row, user) is False
    assert desktop_pairing.deny(row) is False
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_pairing.py -q -o addopts=""`
Expected: FAIL — `AttributeError: … has no attribute 'find_pending'`

- [ ] **Step 3: Implement the three functions**

Append to `app/user_data/desktop_pairing.py`:

```python
def find_pending(raw_user_code):
    """The live, still-undecided pairing for this user code, or None."""
    code = normalise_user_code(raw_user_code)
    if code is None:
        return None
    return (DesktopPairing.objects
            .filter(user_code=code, status=DesktopPairing.PENDING,
                    expires_at__gt=timezone.now())
            .first())


def approve(row, user):
    """Bind the pairing to the signed-in user, if it is still pending.

    A conditional update rather than save(update_fields=...): between
    find_pending() and here the row can be decided by another tab or deleted
    outright by a concurrent redeem(). save() would raise DatabaseError on a
    vanished row (a 500 on the confirmation page) and would happily flip an
    already-decided row's status back. Mirrors passkey_manage.rename_passkey().

    Returns True if this call is the one that decided the pairing.
    """
    return DesktopPairing.objects.filter(
        pk=row.pk, status=DesktopPairing.PENDING,
    ).update(status=DesktopPairing.APPROVED, user=user) == 1


def deny(row):
    """Refuse the pairing, if it is still pending. See approve() on why this is
    a conditional update. Returns True if this call is the one that decided it.
    """
    return DesktopPairing.objects.filter(
        pk=row.pk, status=DesktopPairing.PENDING,
    ).update(status=DesktopPairing.DENIED) == 1
```

`.update()` does not touch the in-memory instance, so callers that want the new
state must `refresh_from_db()`.

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_pairing.py -q -o addopts=""`
Expected: 15 passed

- [ ] **Step 5: Commit**

```bash
git add app/user_data/desktop_pairing.py app/user_data/tests/test_desktop_pairing.py
git commit -m "feat(desktop): look up, approve and deny pairings"
```

---

### Task 5: `redeem()` — poll and mint the token

**Files:**
- Modify: `app/user_data/desktop_pairing.py`
- Test: `app/user_data/tests/test_desktop_pairing.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_desktop_pairing.py`:

```python
from rest_framework.authtoken.models import Token


@pytest.mark.django_db
def test_redeem_pending_returns_pending_and_keeps_the_row():
    device_code, _row = desktop_pairing.begin()
    assert desktop_pairing.redeem(device_code) == {'status': 'pending'}
    assert DesktopPairing.objects.count() == 1


@pytest.mark.django_db
def test_redeem_approved_returns_the_token_and_username():
    device_code, row = desktop_pairing.begin()
    user = User.objects.create_user('alice', password='x')
    desktop_pairing.approve(row, user)

    result = desktop_pairing.redeem(device_code)

    assert result['status'] == 'approved'
    assert result['username'] == 'alice'
    assert result['key'] == Token.objects.get(user=user).key


@pytest.mark.django_db
def test_redeem_approved_is_single_use():
    device_code, row = desktop_pairing.begin()
    user = User.objects.create_user('alice', password='x')
    desktop_pairing.approve(row, user)

    desktop_pairing.redeem(device_code)

    assert DesktopPairing.objects.count() == 0
    with pytest.raises(desktop_pairing.PairingError):
        desktop_pairing.redeem(device_code)


@pytest.mark.django_db
def test_redeem_approved_reuses_the_existing_token():
    user = User.objects.create_user('alice', password='x')
    existing, _ = Token.objects.get_or_create(user=user)
    device_code, row = desktop_pairing.begin()
    desktop_pairing.approve(row, user)
    assert desktop_pairing.redeem(device_code)['key'] == existing.key


@pytest.mark.django_db
def test_redeem_denied_reports_denied_and_consumes_the_row():
    device_code, row = desktop_pairing.begin()
    desktop_pairing.deny(row)
    assert desktop_pairing.redeem(device_code) == {'status': 'denied'}
    assert DesktopPairing.objects.count() == 0


@pytest.mark.django_db
def test_redeem_rejects_unknown_and_expired():
    with pytest.raises(desktop_pairing.PairingError):
        desktop_pairing.redeem('nope')

    device_code, row = desktop_pairing.begin()
    DesktopPairing.objects.filter(pk=row.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1))
    with pytest.raises(desktop_pairing.PairingError):
        desktop_pairing.redeem(device_code)


@pytest.mark.django_db
def test_redeem_rejects_a_non_string_device_code():
    with pytest.raises(desktop_pairing.PairingError):
        desktop_pairing.redeem(None)


@pytest.mark.django_db(transaction=True)
def test_concurrent_redeems_yield_exactly_one_token():
    """Two polls racing: exactly one gets a token, the other gets PairingError.

    transaction=True on purpose: the default django_db runs the whole test in
    one transaction that is rolled back, on a single connection, which cannot
    exercise cross-connection row locking at all. It also means this is the
    only test here where redeem()'s durable atomic block is a real commit --
    Django whitelists nesting durable blocks inside a TestCase's own
    transaction, so everywhere else the durability is a savepoint that never
    lands.
    """
    device_code, row = desktop_pairing.begin()
    user = User.objects.create_user('alice', password='x')
    desktop_pairing.approve(row, user)

    results = []
    errors = []
    barrier = threading.Barrier(2)

    def poll():
        barrier.wait()  # make both threads arrive together
        try:
            results.append(desktop_pairing.redeem(device_code))
        except desktop_pairing.PairingError:
            errors.append(True)
        finally:
            connection.close()  # each thread owns its own connection

    threads = [threading.Thread(target=poll) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive(), 'redeem deadlocked'

    assert len(results) == 1, results
    assert results[0]['status'] == 'approved'
    assert len(errors) == 1
    assert DesktopPairing.objects.count() == 0
```

This needs `import threading` and `connection` added to the `django.db` import.
It is the one test here with teeth against the actual guarantee: verified by
deleting `select_for_update()` from `redeem()`, at which point both threads
receive the same token and the test fails with `assert 2 == 1`.

- [ ] **Step 2: Run it to confirm it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_pairing.py -q -o addopts=""`
Expected: FAIL — `AttributeError: … has no attribute 'redeem'`

- [ ] **Step 3: Implement `redeem()`**

Add the import at the top of `app/user_data/desktop_pairing.py`, beside the other Django imports:

```python
from rest_framework.authtoken.models import Token
```

and append:

```python
def redeem(device_code):
    """Poll a pairing.

    Returns {'status': 'pending'} while the user has not decided,
    {'status': 'denied'} once (the row is consumed), or
    {'status': 'approved', 'key': ..., 'username': ...} once (ditto).

    Raises PairingError for an unknown, expired or already-redeemed code, so
    the caller cannot distinguish "never existed" from "already used" -- both
    are a 400.

    The row is selected FOR UPDATE and deleted in the same transaction that
    mints the token, so two concurrent polls cannot both be served, and a
    crash mid-request leaves the pairing intact for the client to retry.
    """
    if not isinstance(device_code, str):
        raise PairingError()
    with transaction.atomic(durable=True):
        row = (DesktopPairing.objects.select_for_update()
               .filter(device_code_hash=_hash(device_code),
                       expires_at__gt=timezone.now())
               .first())
        if row is None:
            raise PairingError()
        if row.status == DesktopPairing.PENDING:
            return {'status': 'pending'}
        if row.status == DesktopPairing.DENIED:
            row.delete()
            return {'status': 'denied'}
        if row.status != DesktopPairing.APPROVED:
            # Unreachable with today's three statuses. Fail loudly rather than
            # mint a token for a state this function was never taught about.
            raise PairingError('unexpected pairing status %r' % row.status)
        user = row.user
        row.delete()
        token, _created = Token.objects.get_or_create(user=user)
        return {'status': 'approved', 'key': token.key,
                'username': user.username}
```

The token mint is **inside** the block deliberately. It costs one small write
while the row lock is held — and devices never contend, since each holds its
own row (the PK is its own device code hash) — in exchange for making the
delete and the mint one atomic unit, so a crash before commit leaves the
pairing retryable instead of stranding the user.

Do **not** add `select_related('user')` to save the FK query: combined with
`select_for_update()` it makes Postgres lock the joined `auth_user` row on
every 5-second poll unless `of=('self',)` is also passed. One small SELECT is
the better trade.

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_pairing.py -q -o addopts=""`
Expected: 22 passed

- [ ] **Step 5: Commit**

```bash
git add app/user_data/desktop_pairing.py app/user_data/tests/test_desktop_pairing.py
git commit -m "feat(desktop): redeem a pairing for a DRF token, single-use"
```

---

### Task 6: The two API views

**Files:**
- Modify: `app/user_data/passkey_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_desktop_views.py` (create)

- [ ] **Step 1: Write the failing test**

Create `app/user_data/tests/test_desktop_views.py`:

```python
import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient

from user_data import desktop_pairing
from user_data.models import DesktopPairing

BEGIN = '/api/passkeys/desktop/begin/'
POLL = '/api/passkeys/desktop/poll/'


@pytest.fixture
def api():
    return APIClient()


@pytest.mark.django_db
def test_begin_returns_the_handshake(api, settings):
    response = api.post(BEGIN, {}, format='json')

    assert response.status_code == 200
    body = response.json()
    assert len(body['device_code']) >= 40
    assert body['interval'] == 5
    assert body['expires_in'] == settings.PASSKEY_DESKTOP_TTL
    # user_code is the human-facing dashed form, and the URL carries it.
    assert '-' in body['user_code']
    assert body['user_code'] in body['verification_url']
    assert body['verification_url'].startswith('https://')
    assert '/desktop/' in body['verification_url']


@pytest.mark.django_db
def test_begin_rejects_a_non_object_body(api):
    assert api.post(BEGIN, [1, 2], format='json').status_code == 400


@pytest.mark.django_db
def test_poll_reports_pending(api):
    device_code = api.post(BEGIN, {}, format='json').json()['device_code']
    response = api.post(POLL, {'device_code': device_code}, format='json')
    assert response.status_code == 200
    assert response.json() == {'status': 'pending'}


@pytest.mark.django_db
def test_poll_returns_the_token_once_approved(api):
    body = api.post(BEGIN, {}, format='json').json()
    user = User.objects.create_user('alice', password='x')
    row = desktop_pairing.find_pending(body['user_code'])
    desktop_pairing.approve(row, user)

    response = api.post(POLL, {'device_code': body['device_code']}, format='json')

    assert response.status_code == 200
    assert response.json()['status'] == 'approved'
    assert response.json()['username'] == 'alice'
    assert len(response.json()['key']) == 40
    assert DesktopPairing.objects.count() == 0


@pytest.mark.django_db
def test_poll_rejects_unknown_and_reused_codes(api):
    assert api.post(POLL, {'device_code': 'nope'}, format='json').status_code == 400
    assert api.post(POLL, {}, format='json').status_code == 400
    assert api.post(POLL, [1], format='json').status_code == 400


@pytest.mark.django_db
def test_poll_reports_denied(api):
    body = api.post(BEGIN, {}, format='json').json()
    desktop_pairing.deny(desktop_pairing.find_pending(body['user_code']))
    response = api.post(POLL, {'device_code': body['device_code']}, format='json')
    assert response.json() == {'status': 'denied'}


@pytest.mark.django_db
def test_verification_url_follows_the_passkey_web_origin(api, settings):
    # conftest's autouse _passkey_settings fixture pins PASSKEY_WEB_ORIGIN
    # equal to OAUTH_ISSUER_URL, which is exactly why the two being confused
    # is invisible by default. Pull them apart.
    settings.PASSKEY_WEB_ORIGIN = 'https://tunnel.example.org'
    settings.OAUTH_ISSUER_URL = 'https://data.etipitaka.com'

    url = api.post(BEGIN, {}, format='json').json()['verification_url']

    assert url.startswith('https://tunnel.example.org/desktop/?code=')
    assert 'data.etipitaka.com' not in url


@pytest.mark.django_db
def test_poll_rejects_a_code_that_was_already_redeemed(api):
    # The test above named "...unknown_and_reused_codes" never actually reuses
    # one; single-use is only proven a layer down in the service tests.
    body = api.post(BEGIN, {}, format='json').json()
    user = User.objects.create_user('alice', password='x')
    desktop_pairing.approve(desktop_pairing.find_pending(body['user_code']), user)

    first = api.post(POLL, {'device_code': body['device_code']}, format='json')
    second = api.post(POLL, {'device_code': body['device_code']}, format='json')

    assert first.status_code == 200
    assert first.json()['status'] == 'approved'
    assert second.status_code == 400
```

The origin test is only meaningful because it overrides the autouse fixture —
verified by reverting the view to `OAUTH_ISSUER_URL`, at which point it fails.

- [ ] **Step 2: Run it to confirm it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_views.py -q -o addopts=""`
Expected: FAIL — 404s, because the routes do not exist yet

- [ ] **Step 3: Add the views**

Add to the imports at the top of `app/user_data/passkey_views.py`:

```python
from django.conf import settings

from . import desktop_pairing
from . import passkey_config
```

First, give the desktop endpoints their own throttle scope. The shared
`'passkey'` scope is `20/min` keyed on client IP for anonymous callers, but a
desktop client polls at 12 req/min for the life of a pairing — so two machines
behind one NAT (24/min) take continuous 429s. Tests cannot catch this because
the test settings disable throttling.

In `app/etipitaka_auth/settings.py`, add to `DEFAULT_THROTTLE_RATES`:

```python
        # Desktop pairing polls every DESKTOP_POLL_INTERVAL seconds for up to
        # PASSKEY_DESKTOP_TTL, i.e. ~12 req/min for as long as one pairing is
        # open -- sustained traffic the one-shot 'passkey' ceremony budget was
        # never sized for. Anonymous requests key on client IP, so this has to
        # fit several machines sharing one public address (a temple or office
        # behind one NAT): 90/min carries about seven concurrently-pairing
        # clients. Pairing is a brief one-off act, not a steady state, so this
        # is generous in practice.
        'passkey_desktop': '90/min',
```

and — easy to miss, and it makes the suite throttle-dependent if skipped — null
it in the pytest block alongside the existing `login`/`passkey` lines:

```python
REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['passkey_desktop'] = None
```

Then add the throttle class beside the existing two in `passkey_views.py`:

```python
class PasskeyDesktopThrottle(UserRateThrottle):
    """Per client IP for the desktop pairing endpoints (rate: settings
    'passkey_desktop').

    Separate from PasskeyRateThrottle because the traffic shape is different:
    a desktop client polls every few seconds for the life of a pairing, where
    the login/signup ceremonies are two requests and done. Sharing one bucket
    means a second machine behind the same NAT starves the first.

    `rate` is declared explicitly for the same reason as PasskeyRateThrottle.rate.
    """
    scope = 'passkey_desktop'
    rate = None
```

Keying the poll throttle on `device_code` instead of IP was considered and
rejected: any well-formed random code would mint its own fresh bucket, so an
attacker rotating garbage codes would face no limit unless an IP throttle were
kept alongside it anyway.

Append to `app/user_data/passkey_views.py`:

```python
DESKTOP_POLL_INTERVAL = 5  # seconds; the client polls no faster than this


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyDesktopThrottle])
def desktop_begin(request):
    """Start a desktop sign-in handshake.

    Anonymous: the caller is a desktop app that has nobody signed in yet. The
    handshake is worthless without the browser leg, where a signed-in human
    has to confirm the user code.
    """
    if _body(request) is None:
        return _bad_request()
    device_code, row = desktop_pairing.begin()
    user_code = desktop_pairing.format_user_code(row.user_code)
    return Response({
        'device_code': device_code,
        'user_code': user_code,
        # web_origin(), not OAUTH_ISSUER_URL: it returns PASSKEY_WEB_ORIGIN
        # when set, which is the override the docs tell operators to use for
        # an HTTPS tunnel or staging host. Building the URL from the OAuth
        # issuer instead would send the desktop user to a different host than
        # the ceremony is anchored to.
        'verification_url': '%s/desktop/?code=%s' % (
            passkey_config.web_origin(), user_code),
        'interval': DESKTOP_POLL_INTERVAL,
        'expires_in': settings.PASSKEY_DESKTOP_TTL,
    })


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyDesktopThrottle])
def desktop_poll(request):
    data = _body(request)
    if data is None:
        return _bad_request()
    try:
        return Response(desktop_pairing.redeem(data.get('device_code')))
    except desktop_pairing.PairingError:
        return Response({'detail': _('This sign-in request has expired. Please try again.')},
                        status=status.HTTP_400_BAD_REQUEST)
```

- [ ] **Step 4: Add the routes**

In `app/etipitaka_auth/urls.py`, directly after the `api/passkeys/password/remove/` line:

```python
    path('api/passkeys/desktop/begin/', passkey_views.desktop_begin),
    path('api/passkeys/desktop/poll/', passkey_views.desktop_poll),
```

- [ ] **Step 5: Run the tests to confirm they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_views.py -q -o addopts=""`
Expected: 6 passed

- [ ] **Step 6: Commit**

```bash
git add app/user_data/passkey_views.py app/etipitaka_auth/urls.py app/user_data/tests/test_desktop_views.py
git commit -m "feat(desktop): begin and poll API endpoints"
```

---

### Task 7: The confirm page

**Files:**
- Modify: `app/user_data/passkey_web_views.py`
- Create: `app/templates/desktop_confirm.html`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_desktop_views.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_desktop_views.py`:

```python
from django.test import Client

CONFIRM = '/desktop/'
APPROVE = '/desktop/approve/'


@pytest.fixture
def web():
    return Client()


@pytest.mark.django_db
def test_confirm_redirects_an_anonymous_visitor_to_login(web):
    response = web.get(CONFIRM + '?code=K7QP-4M2X')
    assert response.status_code == 302
    assert '/login/' in response['Location']


@pytest.mark.django_db
def test_confirm_shows_the_code_and_the_account(web, api):
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')

    response = web.get(CONFIRM + '?code=' + body['user_code'])

    assert response.status_code == 200
    content = response.content.decode()
    assert body['user_code'] in content
    assert 'alice' in content


@pytest.mark.django_db
def test_confirm_reports_an_unknown_code(web):
    User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')
    response = web.get(CONFIRM + '?code=ZZZZ-9999')
    assert response.status_code == 200
    assert response.context['pairing'] is None


@pytest.mark.django_db
def test_approve_binds_the_pairing_to_the_signed_in_user(web, api):
    body = api.post(BEGIN, {}, format='json').json()
    user = User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')

    response = web.post(APPROVE, {'code': body['user_code'], 'action': 'approve'})

    assert response.status_code == 200
    row = DesktopPairing.objects.get()
    assert row.status == DesktopPairing.APPROVED
    assert row.user == user


@pytest.mark.django_db
def test_approve_with_deny_marks_denied(web, api):
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')

    web.post(APPROVE, {'code': body['user_code'], 'action': 'deny'})

    assert DesktopPairing.objects.get().status == DesktopPairing.DENIED


@pytest.mark.django_db
def test_approve_requires_a_signed_in_user(web, api):
    body = api.post(BEGIN, {}, format='json').json()
    response = web.post(APPROVE, {'code': body['user_code'], 'action': 'approve'})
    assert response.status_code == 302
    assert DesktopPairing.objects.get().status == DesktopPairing.PENDING


@pytest.mark.django_db
def test_approve_ignores_an_unknown_code(web):
    User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')
    response = web.post(APPROVE, {'code': 'ZZZZ-9999', 'action': 'approve'},
                        follow=True)
    assert response.status_code == 200
    assert response.context['pairing'] is None


@pytest.mark.django_db
def test_approve_requires_a_csrf_token(api):
    # The `web` fixture's plain Client() disables CSRF checks entirely, so
    # without this test the protection could be lost and the suite stay green.
    # A forged cross-site POST here would bind a token-granting pairing to the
    # victim's account.
    strict = Client(enforce_csrf_checks=True)
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    strict.login(username='alice', password='secret')

    response = strict.post(APPROVE, {'code': body['user_code'], 'action': 'approve'})

    assert response.status_code == 403
    assert DesktopPairing.objects.get().status == DesktopPairing.PENDING


@pytest.mark.django_db
def test_approve_accepts_a_valid_csrf_token(api):
    strict = Client(enforce_csrf_checks=True)
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    strict.login(username='alice', password='secret')
    strict.get(CONFIRM + '?code=' + body['user_code'])  # mints the CSRF cookie
    token = strict.cookies['csrftoken'].value

    response = strict.post(
        APPROVE, {'code': body['user_code'], 'action': 'approve'},
        HTTP_X_CSRFTOKEN=token, follow=True)

    assert response.status_code == 200
    assert DesktopPairing.objects.get().status == DesktopPairing.APPROVED
```

`test_approve_binds_the_pairing_to_the_signed_in_user` also needs `follow=True`
now that the view redirects.

**On what the CSRF tests actually pin:** verified by mutation. Removing only
`@csrf_protect` leaves them passing, because the global `CsrfViewMiddleware`
(`settings.py`) still enforces it — the decorator is redundant defence in
depth, kept for consistency with `login_passkey`. Removing the middleware too
makes `test_approve_requires_a_csrf_token` fail, with the tokenless POST
approving the pairing. So the test pins the behaviour that matters (this
endpoint refuses a tokenless POST), not one particular layer providing it.

- [ ] **Step 2: Run it to confirm it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_views.py -q -o addopts=""`
Expected: FAIL — 404 on `/desktop/`

- [ ] **Step 3: Add the views**

Add to the imports at the top of `app/user_data/passkey_web_views.py`:

```python
from . import desktop_pairing
```

Append to `app/user_data/passkey_web_views.py`:

Add `require_GET` to the `django.views.decorators.http` import and `redirect`
to the `django.shortcuts` import.

```python
def _no_store(response):
    """These pages show a username and a live pairing code; a shared browser
    must not replay them to the next visitor. Same reasoning as login_passkey.
    """
    response['Cache-Control'] = 'no-store'
    return response


@require_GET
@login_required
@ensure_csrf_cookie
# login_required wraps ensure_csrf_cookie for the same reason as
# account_security above: an anonymous visitor is bounced to LOGIN_URL before
# a CSRF cookie is ever minted for them. /login/ offers passkey sign-in, so
# that bounce is where the passkey ceremony actually happens.
def desktop_confirm(request):
    # After a decision we redirect back here with ?result=..., so a refresh
    # re-runs a harmless GET instead of re-POSTing a decision that has already
    # been made (and would then read as "expired").
    result = request.GET.get('result')
    if result in ('approved', 'denied', 'stale'):
        return _no_store(render(request, 'desktop_confirm.html', {
            'pairing': None,
            'user_code': '',
            'decided': result != 'stale',
            'approved': result == 'approved',
        }))
    pairing = desktop_pairing.find_pending(request.GET.get('code', ''))
    return _no_store(render(request, 'desktop_confirm.html', {
        'pairing': pairing,
        'user_code': (desktop_pairing.format_user_code(pairing.user_code)
                      if pairing else ''),
    }))


@require_POST
@csrf_protect
@login_required
def desktop_approve(request):
    """Bind a pairing to this session's user, or refuse it.

    Anything other than action=approve denies: a user who did not start a
    sign-in on a computer should end up denying, and so should a mangled form.

    Redirects rather than rendering, so a refresh cannot re-submit the
    decision. 'stale' means the pairing was decided by another tab or consumed
    by a concurrent poll between lookup and write.
    """
    pairing = desktop_pairing.find_pending(request.POST.get('code', ''))
    approving = request.POST.get('action') == 'approve'
    # approve()/deny() return False when the pairing was decided by another tab
    # or deleted by a concurrent redeem() since find_pending() saw it. Report
    # the outcome of the write, not the outcome of the lookup -- otherwise the
    # page cheerfully says "signed in" for a decision that never landed.
    applied = False
    if pairing is not None:
        applied = (desktop_pairing.approve(pairing, request.user) if approving
                   else desktop_pairing.deny(pairing))
    if not applied:
        result = 'stale'
    else:
        result = 'approved' if approving else 'denied'
    return _no_store(redirect('/desktop/?result=' + result))
```

- [ ] **Step 4: Create the template**

Create `app/templates/desktop_confirm.html`. The base template and block names
match `account_security.html` (`base.html`, `{% block title %}`, `{% block body %}`
— note it is `body`, not `content`).

```html
{% extends 'base.html' %}

{% load i18n %}

{% block title %}{% trans "Sign in on your computer" %}{% endblock %}

{% block body %}
<div class="container">
  {% if decided %}
    {% if approved %}
      <h3>{% trans "Signed in on your computer" %}</h3>
      <p>{% trans "You can go back to the E-Tipitaka app now." %}</p>
    {% else %}
      <h3>{% trans "Request refused" %}</h3>
      <p>{% trans "Nothing was shared with that computer." %}</p>
    {% endif %}
  {% elif pairing %}
    <h3>{% trans "Did you just choose 'Sign in with a passkey' on your computer?" %}</h3>
    <p>{% blocktrans %}Signed in as {{ user }}{% endblocktrans %}</p>
    <p>{% trans "Your computer should be showing this code:" %}</p>
    <p class="desktop-user-code"><strong>{{ user_code }}</strong></p>
    <p>{% trans "If you did not start this, choose No." %}</p>
    <form method="post" action="/desktop/approve/">
      {% csrf_token %}
      <input type="hidden" name="code" value="{{ user_code }}">
      <button type="submit" name="action" value="approve" class="btn btn-primary">
        {% trans "Yes, allow" %}</button>
      <button type="submit" name="action" value="deny" class="btn btn-default">
        {% trans "No" %}</button>
    </form>
  {% else %}
    <h3>{% trans "This sign-in request has expired" %}</h3>
    <p>{% trans "Start again from the E-Tipitaka app on your computer." %}</p>
  {% endif %}
</div>
{% endblock %}
```

- [ ] **Step 5: Add the routes**

In `app/etipitaka_auth/urls.py`, directly after the `account/security/` line:

```python
    path('desktop/', passkey_web_views.desktop_confirm),
    path('desktop/approve/', passkey_web_views.desktop_approve),
```

- [ ] **Step 6: Run the tests to confirm they pass**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_desktop_views.py -q -o addopts=""`
Expected: 13 passed

- [ ] **Step 7: Commit**

```bash
git add app/user_data/passkey_web_views.py app/templates/desktop_confirm.html app/etipitaka_auth/urls.py app/user_data/tests/test_desktop_views.py
git commit -m "feat(desktop): browser confirmation page for desktop pairing"
```

---

### Task 8: Full suite and the coverage gate

**Files:** none (verification only)

- [ ] **Step 1: Run the whole suite with the gate on**

Run: `docker compose exec -T web python -m pytest`
Expected: all tests pass and coverage stays at or above 90 %.

- [ ] **Step 2: If coverage dropped, add the missing tests**

Run `docker compose exec -T web python -m pytest --cov-report=term-missing` and add cases to `test_desktop_pairing.py` / `test_desktop_views.py` for any uncovered line in `desktop_pairing.py` or the new views. Do not lower the gate.

- [ ] **Step 3: Commit if anything changed**

```bash
git add app/user_data/tests
git commit -m "test(desktop): close coverage gaps in the pairing flow"
```

---

### Task 9: nginx rate limiting

**Files:**
- Modify: `nginx/nginx.conf`

**The desktop API endpoints need their own zone, not `passkey_rl`.** Task 6
gave them a DRF throttle scope of `passkey_desktop` at **90/min**. Putting them
in `passkey_rl` (60 r/m) would make nginx the binding limit, so the DRF scope
would never fire and would be dead config — and the per-IP client budget the
Task 6 fix bought would be silently halved again.

The layering to aim for: **nginx is the coarse outer guard (looser), DRF is the
precise inner limit (tighter).** So the nginx zone must sit above 90/min.

Two other facts that drive the placement: the catch-all
`location ~ ^/api/passkeys(/|$)` at line 212 would otherwise swallow these into
`passkey_manage_rl` (burst 20), and nginx evaluates regex locations top-down,
stopping at the first match. So the new location must appear **before** line
212. It does not need to be near the `(login|signup)` block, since that regex
cannot match a `/desktop/` path.

- [ ] **Step 1: Add the zone**

In `nginx/nginx.conf`, beside the other passkey zones (lines 44-52):

```nginx
# Desktop pairing polls every 5s for up to PASSKEY_DESKTOP_TTL, so sustained
# traffic rather than the login ceremonies' two-shot bursts. The SUSTAINED rate
# sits deliberately above the DRF 'passkey_desktop' scope (2 r/s here vs
# 1.5 r/s there) so that under the traffic shape this is built for -- several
# machines behind one NAT polling steadily -- DRF is the limit that binds and
# this stays the coarse edge backstop.
#
# That ordering holds for sustained rate, NOT for a burst: the two limiters
# have different shapes. nginx is a leaky bucket (burst 60, then 2 r/s), while
# DRF's UserRateThrottle is a sliding window that will pass all 90 in the first
# second. So a flood trips nginx first -- measured, a hot loop gets its first
# 429 from nginx at request ~64, and DRF never fires. That is this zone doing
# its job; do not "fix" it by raising the burst to chase the 90.
limit_req_zone $binary_remote_addr zone=passkey_desktop_rl:10m rate=120r/m;
```

- [ ] **Step 2: Add the API location, above the catch-all**

Insert before the `location ~ ^/api/passkeys(/|$)` block at line 212, copying
the shape of the `(login|signup)` block above it:

```nginx
    # Anonymous desktop pairing (begin once, then poll every 5s for the life
    # of the pairing). Listed ahead of the general /api/passkeys/ location
    # below so this more specific regex wins.
    location ~ ^/api/passkeys/desktop/ {
        limit_req zone=passkey_desktop_rl burst=60 nodelay;
        error_page 429 = @ratelimited_passkey;
        client_max_body_size 64k;
        proxy_pass http://app;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $forwarded_proto;
        proxy_set_header Host $http_host;
        proxy_redirect off;
    }
```

- [ ] **Step 3: Add the browser confirmation page location**

These two routes are plain Django views, so no DRF throttle applies to them at
all — nginx is their only limiter. Without this block they fall through to the
unmetered `location /` catch-all, and `/desktop/approve/` performs a real
database write.

Insert directly after the `location ~ ^/login/passkey/?$ { … }` block that ends
at line 175, copying its shape:

```nginx
    # Desktop pairing confirmation page (the signed-in browser leg of the
    # handshake -- see user_data/desktop_pairing.py). Plain Django views, so
    # unlike the /api/passkeys/ endpoints no DRF throttle backs this up: nginx
    # is the only limiter, and /desktop/approve/ writes to the database.
    # 60r/m is ample for a human pressing one button. `(/|$)`, not a bare
    # trailing slash, so the slash-less GET /desktop is caught too -- Django's
    # APPEND_SLASH 301 would otherwise go through the unmetered location /,
    # same care as /login/passkey/?$ and /api/passkeys(/|$).
    location ~ ^/desktop(/|$) {
        limit_req zone=passkey_rl burst=30 nodelay;
        error_page 429 = @ratelimited_passkey;
        client_max_body_size 64k;
        proxy_pass http://app;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $forwarded_proto;
        proxy_set_header Host $http_host;
        proxy_redirect off;
    }
```

Note `@ratelimited_passkey` returns a JSON body, which is slightly off for an
HTML page. Accepted deliberately: at 60r/m with burst 30 a human clicking one
button will never see it, and adding a fourth named 429 handler for a case that
should not occur is not worth the config surface.

- [ ] **Step 4: Check the config parses**

`nginx/Dockerfile` bakes the config in with `COPY nginx.conf /etc/nginx/conf.d`
— there is no volume mount, so a bare `nginx -t` tests the image's copy and
will happily pass while your edit sits unread on the host. Copy it in first.

Note the destination is **`/etc/nginx/conf.d/nginx.conf`**, not
`/etc/nginx/nginx.conf`. This repo's `nginx/nginx.conf` is an http-context
fragment (it starts with `map`/`limit_req_zone`, no `events`/`http` wrapper).
Writing it over the image's main `/etc/nginx/nginx.conf` clobbers that file and
fails with `"map" directive is not allowed here`.

```bash
docker compose cp nginx/nginx.conf nginx:/etc/nginx/conf.d/nginx.conf
docker compose exec -T nginx nginx -t
docker compose exec -T nginx nginx -s reload
```

Expected: `syntax is ok` / `test is successful`, then `signal process started`.

- [ ] **Step 5: Prove each location is bound to the zone you think it is**

`nginx -t` only proves the file parses. It does not prove the new locations
match ahead of the `^/api/passkeys(/|$)` catch-all — get that wrong and the
endpoints silently inherit `passkey_manage_rl` (burst 20) with no error
anywhere. Measure where the first 429 appears on each path; the burst sizes
differ enough to tell the zones apart.

The app must actually be up for this to mean anything — if the endpoint is
500ing, you are measuring nginx against an error page. Check for a 200 first:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  http://localhost:1338/api/passkeys/desktop/begin/ \
  -H 'Content-Type: application/json' -d '{}'
```

Expected `200`. A 500 here is usually a stale container: `user_data/migrations`
is bind-mounted but gunicorn workers hold the module they imported at start, so
after adding the model you need `docker compose exec -T web python manage.py
migrate user_data` and `docker compose restart web`.

Then, for each path, count requests until the first 429:

```bash
for p in /api/passkeys/desktop/begin/ /api/passkeys/ /desktop; do
  for i in $(seq 1 130); do
    R=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:1338$p")
    [ "$R" = "429" ] && { echo "$p -> first 429 at #$i"; break; }
  done
done
```

Expected, and these numbers are the actual assertion:
- `/api/passkeys/desktop/begin/` → ~**64** (burst 60 + replenish) = `passkey_desktop_rl` ✓
- `/api/passkeys/` → ~**22** (burst 20 + replenish) = `passkey_manage_rl`, the
  control proving the two locations really are on different zones
- `/desktop` **slash-less** → ~**32** (burst 30 + replenish) = `passkey_rl`,
  proving the `(/|$)` alternation works. Before that fix this ran all 130
  without a 429, because it fell through to the unmetered `location /`.

The 429 body must be nginx's `{"error":"rate_limited",...}`. If you instead see
DRF's `{"detail":"Request was throttled..."}`, nginx is not limiting that path
at all and something above is wrong.

- [ ] **Step 6: Commit**

```bash
git add nginx/nginx.conf
git commit -m "feat(desktop): rate limit the pairing endpoints"
```

---

### Task 10: Thai translations

**Files:**
- Modify: `app/locale/th/LC_MESSAGES/django.po` (and the compiled `.mo`)

- [ ] **Step 1: Extract the new strings**

Run: `docker compose exec -T web python manage.py makemessages -l th`
Expected: the new `desktop_confirm.html` and `passkey_views.py` strings appear as untranslated entries.

- [ ] **Step 2: Translate every new msgid**

Fill in the Thai for each. Suggested wording, matching the tone of the existing passkey pages:

| msgid | Thai |
|---|---|
| `Sign in on your computer` | `เข้าสู่ระบบบนคอมพิวเตอร์` |
| `Did you just choose 'Sign in with a passkey' on your computer?` | `คุณเพิ่งกด "เข้าสู่ระบบด้วย Passkey" บนคอมพิวเตอร์ใช่ไหม?` |
| `Signed in as %(user)s` (the `blocktrans`) | `เข้าสู่ระบบในชื่อ %(user)s` |
| `Your computer should be showing this code:` | `คอมพิวเตอร์ของคุณควรแสดงรหัสนี้:` |
| `If you did not start this, choose No.` | `ถ้าคุณไม่ได้เริ่มการเข้าสู่ระบบนี้ ให้เลือก "ไม่ใช่"` |
| `Yes, allow` | `ใช่ อนุญาต` |
| `No` | `ไม่ใช่` |
| `Signed in on your computer` | `เข้าสู่ระบบบนคอมพิวเตอร์แล้ว` |
| `You can go back to the E-Tipitaka app now.` | `กลับไปที่โปรแกรม E-Tipitaka ได้เลย` |
| `Request refused` | `ปฏิเสธคำขอแล้ว` |
| `Nothing was shared with that computer.` | `ไม่มีข้อมูลใดถูกส่งไปยังคอมพิวเตอร์เครื่องนั้น` |
| `This sign-in request has expired` | `คำขอเข้าสู่ระบบนี้หมดอายุแล้ว` |
| `This sign-in request has expired. Please try again.` | `คำขอเข้าสู่ระบบนี้หมดอายุแล้ว กรุณาลองใหม่` |
| `Start again from the E-Tipitaka app on your computer.` | `เริ่มใหม่จากโปรแกรม E-Tipitaka บนคอมพิวเตอร์ของคุณ` |

- [ ] **Step 3: Compile**

Run: `docker compose exec -T web python manage.py compilemessages -l th`

- [ ] **Step 4: Run the i18n tests**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_i18n.py user_data/tests/test_passkey_i18n.py -q -o addopts=""`
Expected: PASS. `test_i18n.py` compares `.mo` content against the `.po`, so a stale `.mo` fails here — recompile if it does.

- [ ] **Step 5: Commit**

```bash
git add app/locale
git commit -m "feat(desktop): Thai translations for the pairing page"
```

---

### Task 11: Golden snapshots

**Files:**
- Modify: `tests/golden/` (a new case plus its snapshot)

The harness is declarative: cases live in `tests/golden/endpoints.py` as
`GoldenCase(...)`, and `tests/golden/normalize.py` masks values that change per
request. Today it masks only `challenge` and `challenge_id`
(`normalize.py:24`), so the three volatile desktop fields need adding or the
snapshot will never match twice.

- [ ] **Step 1: Add the case**

In `tests/golden/endpoints.py`, directly after the `passkey_login_begin` line
(currently line 84), add:

```python
    GoldenCase("desktop_begin", "POST", "/api/passkeys/desktop/begin/", json_body={}),
```

- [ ] **Step 2: Mask the volatile fields**

In `tests/golden/normalize.py`, extend the key check at line 24 so it also
covers the pairing fields:

```python
            elif key in ("challenge", "challenge_id",
                         "device_code", "user_code", "verification_url"):
                # WebAuthn challenges are random per request; so are the
                # desktop pairing codes, and verification_url embeds the
                # user_code.
```

`interval` and `expires_in` are deliberately left unmasked — they are part of
the contract the desktop client depends on and should break the snapshot if
they ever change.

- [ ] **Step 3: Seed and run**

```bash
docker compose exec -T web python manage.py seed_golden
tests/golden/.venv/bin/python -m pytest tests/golden --base-url http://localhost:1338
```
Expected: PASS, with the new snapshot written on first run — inspect it before committing.

- [ ] **Step 4: Commit**

```bash
git add tests/golden
git commit -m "test(golden): snapshot the desktop pairing begin response"
```

---

### Task 12: End-to-end leg

**Files:**
- Modify: `tests/passkey_e2e.py`

- [ ] **Step 1: Read the existing script**

`tests/passkey_e2e.py:180-250` is a working reference client in plain `urllib`, already covering the browser `/login/passkey/` + CSRF dance. The desktop leg reuses that session.

- [ ] **Step 2: Add the desktop leg**

After the existing browser-login section, add a function that:
1. POSTs `{}` to `/api/passkeys/desktop/begin/` and keeps `device_code` + `user_code`
2. polls `/api/passkeys/desktop/poll/` once and asserts `{'status': 'pending'}`
3. GETs `/desktop/?code=<user_code>` with the logged-in session and asserts the code appears in the HTML
4. POSTs `/desktop/approve/` with `code`, `action=approve` and the CSRF token
5. polls again and asserts `status == 'approved'`, that `key` matches the token `/rest-auth/login/` returns for the same user, and that a third poll is now a 400

- [ ] **Step 3: Run it**

Run: `python tests/passkey_e2e.py` against a running stack (see the header of that file for how it takes its base URL).
Expected: the new leg passes alongside the existing ones.

- [ ] **Step 4: Commit**

```bash
git add tests/passkey_e2e.py
git commit -m "test(e2e): desktop pairing begin, approve and poll"
```

---

### Task 13: Client integration docs

**Files:**
- Modify: `docs/passkeys-client-integration.md`

- [ ] **Step 1: Add a desktop section**

Add a "Desktop (browser-delegated)" section covering: why a desktop client cannot post credential JSON directly (the single allowed origin), the two endpoints with their exact request and response bodies, the `interval` / `expires_in` contract, that an approved pairing is single-use, that a 400 from poll means expired-or-already-used, and the three browser URLs a desktop client should open for sign-up, passkey management and recovery.

- [ ] **Step 2: Commit**

```bash
git add docs/passkeys-client-integration.md
git commit -m "docs(passkey): document the desktop pairing flow"
```

---

### Task 14: Deploy and verify live

**Files:** none

- [ ] **Step 1: Run the full suite one last time**

Run: `docker compose exec -T web python -m pytest`
Expected: green, coverage at or above 90 %.

- [ ] **Step 2: Deploy**

Run the repo's usual `./deploy.sh`. It applies migrations and curl-checks the well-known files afterwards.

- [ ] **Step 3: Verify the live endpoint by hand**

```bash
curl -fsS -X POST https://data.etipitaka.com/api/passkeys/desktop/begin/ \
  -H 'Content-Type: application/json' -d '{}'
```
Expected: JSON with `device_code`, a dashed `user_code`, a `verification_url` on `https://data.etipitaka.com/desktop/`, `interval: 5`, `expires_in: 600`.

- [ ] **Step 4: Walk the browser leg once**

Open the `verification_url` in a real browser, sign in with a passkey, confirm the code, then poll with the `device_code` from Step 3 and check a token comes back. This is the proof the client plan depends on.

---

## Verification checklist

- [ ] `docker compose exec -T web python -m pytest` green, coverage ≥ 90 %
- [ ] `docker compose exec -T nginx nginx -t` clean
- [ ] Golden snapshots pass against a freshly seeded stack
- [ ] `tests/passkey_e2e.py` passes including the new leg
- [ ] Live `begin` returns the expected JSON
- [ ] One full manual browser leg produces a working token
- [ ] No change to `passkey_service.py`, `passkey_login.js` or any existing endpoint's behaviour
