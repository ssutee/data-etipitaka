# Django + Python 3 Migration — Design

**Date:** 2026-05-21
**Project:** data-etipitaka — E-Tipitaka-Plus Account backend
**Goal:** Migrate from Python 2.7 / Django 1.9 to Python 3.13 / Django 5.2 LTS, with a regression test suite proving behavior is unchanged.

## Summary

The backend is small (~300 lines of app code: 12 view functions, 3 models, 1 form, Django 1.9 config). It serves the E-Tipitaka-Plus iOS client. The migration spans 16 Django releases and a Python major version, and replaces an abandoned auth stack.

The work is gated by a cross-stack **golden test harness**: every endpoint's current behavior is recorded against the running old app *before* any code changes, then the migrated app must reproduce those recordings byte-for-byte (after normalization).

## Decisions (locked)

| Topic | Decision |
|---|---|
| Test timing | Characterization tests written first, against the old stack |
| Target Django | 5.2 LTS |
| Target Python | 3.13 |
| Strategy | Big-bang rewrite to 5.2 (codebase small enough); existing migration history kept |
| Auth stack | Drop `allauth` + `django-rest-auth`; reimplement endpoints DRF-native |
| Email verification | Reimplemented in DRF (stateless signed token), **mandatory** — deliberate behavior change from the current `ACCOUNT_EMAIL_VERIFICATION='optional'` |
| Test approach | External HTTP golden harness (stack-agnostic) + Django unit tests on the new stack |
| CI | GitHub Actions workflow running both suites — in scope |

## Section 1 — Target end state

### Stack

| Component | From | To |
|---|---|---|
| Python | 2.7 | 3.13 |
| Django | 1.9 | 5.2 LTS |
| djangorestframework | 3.3.1 | 3.16.x |
| DB driver | psycopg2 2.7.1 | psycopg3 (`psycopg[binary]` 3.2.x) |
| gunicorn | 19.7.1 | 23.x |
| python-dateutil | 2.4.2 | 2.9.x (kept — iOS sends arbitrary timestamp formats) |

**Dropped entirely:** `django-allauth`, `django-rest-auth`, `python-openid`, `oauthlib`, `requests-oauthlib`.

### Docker

- `app/Dockerfile` base image `frolvlad/alpine-python2` → `python:3.13-slim`. `psycopg[binary]` ships wheels, so the compile/build stage (`gcc`, `postgresql-dev`, `musl-dev`) is removed.
- `docker-compose.yml`: `platform: linux/amd64` removed (Python 3 images are multi-arch).
- `nginx` stays at `1.27-alpine`. **Postgres is bumped `12.0` → `16-alpine`** — Django 5.2 hard-requires PostgreSQL 14+ and refuses to connect to PG12, so this is a mandatory part of the migration, not optional.

### Repo layout

```
app/                      Django project (migrated in place)
tests/golden/             NEW — standalone pytest+requests harness (no Django import)
tests/golden/snapshots/   NEW — recorded golden responses
app/user_data/tests/      NEW — Django unit tests (new stack only)
.github/workflows/        NEW — CI workflow
```

End state: identical URLs, identical API contract, identical DB schema — new stack underneath.

## Section 2 — Golden harness

A standalone `pytest` + `requests` suite that talks to the running app over HTTP only. It never imports Django, so the same test code runs unchanged against both the old (Python 2 / Django 1.9) and new (Python 3 / Django 5.2) app.

### Endpoint inventory (21 URL patterns)

- **App data views (13):** `/`, `/sync_data_list/`, `/user_list/`, `/sharing_list/`, `/user/<pk>/`, `/user/<pk>/<name>/`, `/sync_data/` (POST), `/sync_data/<name>/`, `/user_data/`, `/user_data_list/`, `/user_data/<pk>/` (GET/DELETE), `/follower/<pk>/` (POST/DELETE), `/upload/` (POST)
- **Auth views (2 + templates):** `/login/` (GET/POST), `/signup/`, `/signup/validate/`
- **Reimplemented stack (3):** `/rest-auth/*`, `/rest-auth/registration/*`, `/account/*` — contract captured here so the DRF rebuild can match it
- **`/admin/`:** smoke-check only (Django builtin, not project code)

### Seed dataset

A deterministic fixture: fixed users with known auth tokens, known `SyncData` / `UserData` / `Sharing` rows, small fixture upload files. The same seed loads into the old and new app so PKs, file paths, and usernames match across runs. The fixture only references models that survive the migration (`auth.user`, `authtoken.token`, `user_data.*`), so Django 1.9 can load it.

### Cases per endpoint

Each endpoint is exercised across: authed / unauthed / valid input / invalid input / target exists / target missing (404). Each case records a snapshot of `(status code, selected headers, body)`.

### Normalization

Volatile fields are stripped or masked before comparison:

- `created_at` timestamps, session cookies, CSRF tokens
- File-download responses: store `Content-Type` + `Content-Disposition` + **md5 hash of body bytes**, not raw bytes

### Run modes

- `--record`: write `tests/golden/snapshots/*.json` (run against the old app)
- default: assert the new app's responses against the recorded snapshots

### Known gap

Email-verification tokens are time- and secret-based — they cannot be byte-matched across runs. Those endpoints get **behavioral assertions** (account starts inactive → email sent → token verifies → account active), not golden snapshots.

## Section 3 — Code migration

### Python 2 → 3

- `models.py`: remove `from __future__ import unicode_literals`; remove unused `from urlparse import urljoin`
- `settings.py:169`: `from local_settings import *` → `from .local_settings import *` (implicit relative import removed in Python 3)
- Byte/string handling (`hashlib.md5(open(..., 'rb'))`, etc.) is already Python 3-safe

### Django 1.9 → 5.2

- `urls.py`: string view references (`'user_data.views.index_view'`) were removed in Django 1.10 — import the view callables and switch `url()` → `path()` / `re_path()`
- `views.py:217`: `request.user.is_authenticated()` → `request.user.is_authenticated` (property, no call)
- `models.py`: every `ForeignKey` needs an explicit `on_delete=` → `models.CASCADE` (Django 1.9's implicit default — preserves current delete behavior; the spec's earlier `SET_NULL` would have changed behavior)
- migrations `0001`–`0004`: **no patching needed** — Django 1.9's migration generator already wrote `on_delete=CASCADE` into every `ForeignKey` (verified during planning)
- `settings.py`: `MIDDLEWARE_CLASSES` → `MIDDLEWARE`; remove allauth / rest_auth entries from `INSTALLED_APPS` and `AUTHENTICATION_BACKENDS`; `django.core.urlresolvers` → `django.urls` if referenced
- `views.py:9`: remove the unused `verified_email_required` import
- templates: `{% load staticfiles %}` (template tag library removed in Django 3.0) → `{% load static %}`

### Registration behavior change

Current `ACCOUNT_EMAIL_VERIFICATION='optional'` means signup creates an *active* account today. Per explicit user decision during planning, the rebuild makes verification **mandatory**: `/rest-auth/registration/` creates `User(is_active=False)`; the account cannot log in until the emailed token is verified. This is the one intentional behavior change in the migration — the iOS client's post-signup flow must handle a "not yet verified" state. All other endpoints preserve behavior exactly.

### DRF-native auth rebuild

New endpoints keep the **same URL paths**; their contract is matched to the golden snapshots from Section 2.

- `/rest-auth/login/` — token obtain, response shape `{"key": "..."}`
- `/rest-auth/logout/` — delete the user's token
- `/rest-auth/registration/` — create `User(is_active=False)`, email a verification link
- `/rest-auth/registration/verify-email/` — validate token → `is_active=True`
- `/account/*` — reimplement only the email-confirm landing page the verification link points to
- Email-verification token: `django.core.signing.TimestampSigner` — a stateless signed token with built-in expiry; no new model
- Anything the old allauth stack did that the iOS client never calls is dropped, not rebuilt — the golden snapshots define the target surface

### New file layout

New auth code lives in `app/user_data/auth_views.py` and `app/user_data/auth_urls.py`, keeping the 12 data views untouched and isolating the rebuilt auth surface.

## Section 4 — Migrations & data

### `on_delete` migrations

Django's `on_delete` is application-level, not a database constraint — adding it produces **no SQL**. Migrations `0001`–`0004` are patched in place so `makemigrations` reports no changes. Existing tables are unchanged.

### The `dump.json` problem

The current 7804-object fixture includes `account.emailaddress`, `socialaccount.*`, and `contenttypes` rows for removed apps. Once allauth is dropped, `loaddata dump.json` fails — those models no longer exist.

Two data paths:

1. **Production DB (existing data):** the Django *schema* is unchanged, but the Postgres *server* must move from 12 to 16 (Django 5.2 requires PG14+). A PG16 server will not start on a PG12 data directory, so production cutover requires a one-time PG12→PG16 data upgrade (`pg_upgrade` or dump/restore — see the production upgrade task in the implementation plan). Once on PG16, the new app runs `migrate` → no-ops (schema unchanged). The old `allauth` / `socialaccount` tables become harmless orphans (an optional cleanup migration can drop them later). No application-data loss — but the DB upgrade is a required, non-trivial cutover step.
2. **Fresh / CI / test environments:** generate a filtered `app/seed.json` keeping only `auth.user`, `authtoken.token`, `user_data.*`. `init.sh` loads `seed.json` instead of `dump.json`.

### Verified-email state

allauth gated login on `account.emailaddress.verified`. The new design gates on `User.is_active`. Existing users keep their current `is_active` value, so already-active users continue to log in. The dropped `emailaddress` rows are not needed.

### Untouched

`media_volume` user uploads (`UserData` / `SyncData` files) are never touched by the migration.

## Section 5 — Deployment & testing

### Docker

- `app/Dockerfile`: single-stage on `python:3.13-slim`; `psycopg[binary]` removes the need for a build stage
- `docker-compose.yml`: `platform: linux/amd64` removed
- `init.sh`: `docker-compose` → `docker compose`; `loaddata dump.json` → `loaddata seed.json`
- `entrypoint.sh` (nc-wait loop) and `nginx` config unchanged

### Test suites

**Golden harness** (`tests/golden/`, cross-stack) — see Section 2.

**Django unit tests** (`app/user_data/tests/`, new stack, `pytest` + `pytest-django`) — covers every function:

- `user_directory_path()` — pure-function test
- 3 models — creation, field defaults (`deleted=False`, `created_at` auto-set), FK behavior
- `UploadFileForm` — valid and invalid input
- 12 data views — per-branch: auth required, 404 paths, method split (GET/POST/DELETE), `upload_view` file-exists branch, `user_data_action` soft-delete branch, `upload_sync_data` checksum calculation, `download_user_data` sharing access-deny
- New auth views — token login, logout, registration (inactive user + email sent via the in-memory mail backend), verify-email (valid / expired / tampered token)

### Coverage

`coverage.py`, target 100% of functions and ≥90% of lines.

### CI

A GitHub Actions workflow (`.github/workflows/`) runs both suites on every push:

1. Build the new-stack image, start the service + Postgres
2. Run the Django unit suite with coverage
3. Run the golden harness against the started service, assert against committed snapshots

## Section 6 — Work sequencing

Six phases, each its own commit(s). Each phase gates the next.

**Phase 0 — Golden harness (old stack).** Old app already runs in Docker. Define the deterministic seed fixture, build `tests/golden/`, run `--record`, commit snapshots. Mandatory before any code change.

**Phase 1 — Migrate code to Python 3 / Django 5.2.** `requirements.txt`, Dockerfile → `python:3.13-slim`, Python 2→3 fixes, Django 1.9→5.2 fixes, patched migrations. Goal: app boots on the new stack.

**Phase 2 — DRF-native auth rebuild.** `auth_views.py` / `auth_urls.py` — login, logout, registration, verify-email, email-confirm landing. Generate filtered `seed.json`.

**Phase 3 — Verify against golden harness.** Run the harness against the new app, diff against Phase 0 snapshots, fix until green. Email-verify endpoints checked with behavioral assertions.

**Phase 4 — Django unit tests.** Full per-function suite on the new stack, `coverage.py` to target.

**Phase 5 — Deployment cleanup.** `init.sh` fix, CI workflow, update `CLAUDE.md`.

**Gating:** 0 → 1 → 2 → 3 → 4 → 5. Phase 0 must finish before any code change. Phase 3 must be green before Phase 4.

**Rollback:** all work on a feature branch; production Postgres untouched until cutover, so the old stack stays recoverable via git.

## Out of scope

- (Postgres 12→16 is now IN scope — Django 5.2 requires PG14+. See the implementation plan's production upgrade task.)
- Refactoring or feature changes to the 12 data views — behavior is preserved exactly
- Re-architecting URL paths — paths are kept identical so the iOS client needs no change

## Success criteria

1. App runs on Python 3.13 / Django 5.2 LTS via `docker compose up`
2. Golden harness passes against the new app (matches Phase 0 recordings)
3. Every function has unit-test coverage; `coverage.py` meets target
4. CI runs both suites green on every push
5. The iOS client requires no change — URLs and API contract are unchanged
