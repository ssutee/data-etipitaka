# Django 5.2 / Python 3 Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the data-etipitaka backend from Python 2.7 / Django 1.9 to Python 3.13 / Django 5.2 LTS, with a cross-stack golden test harness and full unit-test coverage proving behavior is unchanged.

**Architecture:** A standalone HTTP "golden harness" records every endpoint's response against the running old app, then asserts the migrated app reproduces them. The app is migrated big-bang to Django 5.2; the abandoned `allauth`/`rest-auth` auth stack is rebuilt DRF-native at the same URL paths. Email verification becomes mandatory (a deliberate, approved behavior change).

**Tech Stack:** Python 3.13, Django 5.2 LTS, djangorestframework 3.16, psycopg3, gunicorn 23, pytest + pytest-django, Docker Compose, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-05-21-django-python3-migration-design.md`

---

## Corrections to the spec discovered during planning

1. **Migrations need no patching** — Django 1.9 already wrote `on_delete=CASCADE` into every `ForeignKey` in migrations `0001`/`0003`/`0004`. Only `models.py` lacks `on_delete`.
2. **`on_delete` value is `CASCADE`, not `SET_NULL`** — Django 1.9's implicit FK default was `CASCADE`. Using `SET_NULL` would change delete behavior. The plan uses `CASCADE`.
3. **Templates use `{% load staticfiles %}`** — that tag library was removed in Django 3.0. Must become `{% load static %}`.
4. **Registration is now mandatory-verification** — approved behavior change; the current setting is `ACCOUNT_EMAIL_VERIFICATION='optional'` (active-on-signup).
5. **`signup_form.html` posts to URL name `rest_register`** — the rebuilt registration endpoint must keep that exact `name=`.
6. **The real database config lives in `local_settings.py`** — `settings.py` declares sqlite3 but `local_settings.py` overrides it with Postgres.

## Corrections discovered during execution (Task 1.10)

7. **Postgres must be bumped 12 → 16** — Django 5.2 hard-requires PostgreSQL 14+ and refuses to connect to PG12 (`NotSupportedError`). `docker-compose.yml` `db` service is now `postgres:16-alpine`. This is mandatory, not the deferred follow-up the spec originally assumed. Consequences: any task that resets the DB must also wipe the `postgres_data` volume (a PG16 server cannot start on a PG12 data dir); production cutover needs a one-time PG12→PG16 data upgrade — see Task 5.3.
8. **`django.contrib.messages` is required in `INSTALLED_APPS`** — Django's admin fails the `admin.E406` system check without it. It was dropped in the Phase 1 settings rewrite (Task 1.5) and has been added back.
   (Both corrections 7 and 8 were committed during Task 1.10 as `fix: bump Postgres to 16 and add messages app for Django 5.2`.)
9. **`EMAIL_BACKEND` defaults to the console backend** — `rest_register` sends a verification email via `send_mail`. The original `smtp` backend would make the live dev/CI server attempt real SMTP delivery (and Phase 3's behavioral registration test would too). `settings.py` now defaults `EMAIL_BACKEND` to `django.core.mail.backends.console.EmailBackend`; production overrides it via deployment config. (Task-suite runs still force the `locmem` backend per Task 4.1.) Committed before Task 2.6.

## File structure

**Phase 0 — golden harness** (all new):
```
tests/golden/requirements.txt          pytest + requests pins
tests/golden/conftest.py               pytest options + http/base_url fixtures
tests/golden/endpoints.py              endpoint case spec table
tests/golden/normalize.py              response normalization
tests/golden/snapshot.py               snapshot save/load
tests/golden/test_golden.py            parametrized golden test
tests/golden/test_behavioral.py        registration/verify behavioral tests
tests/golden/snapshots/*.json          recorded golden responses (generated)
tests/golden/README.md                 how to run
app/user_data/management/__init__.py
app/user_data/management/commands/__init__.py
app/user_data/management/commands/seed_golden.py   deterministic dataset (Django 1.9 + 5.2 compatible)
app/user_data/management/commands/seed_files/*     fixture upload files
```

**Phase 1 — migration** (modify):
```
app/requirements.txt          app/Dockerfile          docker-compose.yml
app/user_data/models.py       app/etipitaka_auth/settings.py
app/etipitaka_auth/local_settings.py                  app/etipitaka_auth/urls.py
app/user_data/views.py        app/templates/*.html
```

**Phase 2 — auth rebuild** (new + modify):
```
app/user_data/serializers.py  (new)    app/user_data/auth_views.py  (new)
app/user_data/auth_urls.py    (new)    app/templates/email/verify_email.txt (new)
app/etipitaka_auth/urls.py    (modify) init.sh (modify)
app/seed.json                 (new — filtered fixture)
```

**Phase 4 — unit tests** (new):
```
app/pytest.ini                app/requirements-dev.txt
app/user_data/tests/__init__.py   test_models.py   test_forms.py
app/user_data/tests/test_views.py   test_auth.py
```
(Delete the placeholder `app/user_data/tests.py`.)

**Phase 5 — CI** (new): `.github/workflows/ci.yml`; modify `CLAUDE.md`.

---

# Phase 0 — Golden harness (old stack)

The old app is currently running via `docker compose up` (Python 2 / Django 1.9). Phase 0 builds the harness and records snapshots against it. **No app code changes in this phase.**

### Task 0.1: Harness scaffolding

**Files:**
- Create: `tests/golden/requirements.txt`
- Create: `tests/golden/conftest.py`
- Create: `tests/golden/README.md`

- [ ] **Step 1: Create `tests/golden/requirements.txt`**

```
pytest==8.3.4
requests==2.32.3
```

- [ ] **Step 2: Create `tests/golden/conftest.py`**

```python
import os
import pytest
import requests


def pytest_addoption(parser):
    parser.addoption(
        "--record", action="store_true", default=False,
        help="Record golden snapshots instead of asserting against them",
    )
    parser.addoption(
        "--base-url", action="store",
        default=os.environ.get("GOLDEN_BASE_URL", "http://localhost:1338"),
        help="Base URL of the running app under test",
    )


@pytest.fixture(scope="session")
def record(pytestconfig):
    return pytestconfig.getoption("--record")


@pytest.fixture(scope="session")
def base_url(pytestconfig):
    return pytestconfig.getoption("--base-url").rstrip("/")


@pytest.fixture(scope="session")
def http():
    session = requests.Session()
    yield session
    session.close()
```

- [ ] **Step 3: Create `tests/golden/README.md`**

```markdown
# Golden test harness

Cross-stack HTTP regression harness. Talks to the app over HTTP only — no Django import — so the same tests run against the old (Py2/Django1.9) and new (Py3/Django5.2) stack.

## Setup

    python3 -m venv .venv && . .venv/bin/activate
    pip install -r tests/golden/requirements.txt

## Record (against the OLD app)

    docker compose up -d
    docker compose exec web python manage.py seed_golden
    pytest tests/golden/test_golden.py --record --base-url http://localhost:1338

## Assert (against the NEW app, after migration)

    docker compose up -d
    docker compose exec web python manage.py seed_golden
    pytest tests/golden -v --base-url http://localhost:1338

A failing test = a behavior regression.
```

- [ ] **Step 4: Commit**

```bash
git add tests/golden/requirements.txt tests/golden/conftest.py tests/golden/README.md
git commit -m "test: scaffold golden harness"
```

### Task 0.2: `seed_golden` management command

Creates a deterministic dataset. Must run on **both** Django 1.9 (Python 2) and Django 5.2 (Python 3) — no f-strings, no Py3-only syntax.

**Files:**
- Create: `app/user_data/management/__init__.py` (empty)
- Create: `app/user_data/management/commands/__init__.py` (empty)
- Create: `app/user_data/management/commands/seed_golden.py`
- Create: `app/user_data/management/commands/seed_files/sync_alice.json`
- Create: `app/user_data/management/commands/seed_files/data_alice.json`
- Create: `app/user_data/management/commands/seed_files/upload_payload.json`

- [ ] **Step 1: Create the two empty `__init__.py` files**

```bash
mkdir -p app/user_data/management/commands/seed_files
touch app/user_data/management/__init__.py app/user_data/management/commands/__init__.py
```

- [ ] **Step 2: Create the seed fixture files** (small, fixed-content)

`app/user_data/management/commands/seed_files/sync_alice.json`:
```json
{"seed": "sync_alice", "version": 1}
```
`app/user_data/management/commands/seed_files/data_alice.json`:
```json
{"seed": "data_alice", "version": 1}
```
`app/user_data/management/commands/seed_files/upload_payload.json`:
```json
{"seed": "upload_payload", "version": 1}
```

- [ ] **Step 3: Create `app/user_data/management/commands/seed_golden.py`**

```python
# -*- coding: utf-8 -*-
import os
import shutil

from django.conf import settings
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from rest_framework.authtoken.models import Token

from user_data.models import UserData, SyncData, Sharing

ALICE_TOKEN = "a1ce000000000000000000000000000000000001"
BOB_TOKEN = "b0b0000000000000000000000000000000000002"
SEED_DIR = os.path.join(os.path.dirname(__file__), "seed_files")


class Command(BaseCommand):
    help = "Create the deterministic golden-test dataset (idempotent)."

    def handle(self, *args, **options):
        # Wipe prior golden data. Keep superusers.
        Sharing.objects.all().delete()
        SyncData.objects.all().delete()
        UserData.objects.all().delete()
        Token.objects.all().delete()
        User.objects.filter(is_superuser=False).delete()

        alice = self._user(1001, "alice", "alice@example.com", "alicepass123")
        bob = self._user(1002, "bob", "bob@example.com", "bobpass123")

        Token.objects.create(key=ALICE_TOKEN, user=alice)
        Token.objects.create(key=BOB_TOKEN, user=bob)

        # bob owns sync data; alice follows bob (so alice may download bob's data).
        self._syncdata(2001, bob, "sync_alice.json", "ios", "2020-01-01T00:00:00+00:00")
        self._syncdata(2002, alice, "sync_alice.json", "ios", "2020-01-02T00:00:00+00:00")
        Sharing.objects.create(id=4001, owner=bob, follower=alice)

        # alice has two UserData rows: one live, one soft-deleted.
        self._userdata(3001, alice, "data_alice.json", "ios", False)
        self._userdata(3002, alice, "data_alice.json", "ios", True)

        self.stdout.write("seed_golden: done")

    def _user(self, pk, username, email, password):
        user = User(pk=pk, username=username, email=email, is_active=True)
        user.set_password(password)
        user.save()
        return user

    def _place(self, rel_path, src_name):
        dest = os.path.join(settings.MEDIA_ROOT, rel_path)
        parent = os.path.dirname(dest)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        shutil.copy(os.path.join(SEED_DIR, src_name), dest)
        return rel_path

    def _syncdata(self, pk, user, src_name, platform, created_at):
        rel = "%s/%s/%s" % (user.username, platform, src_name)
        self._place(rel, src_name)
        row = SyncData(pk=pk, user=user, name=src_name, platform=platform,
                       checksum="seedchecksum")
        row.file.name = rel
        row.save()
        SyncData.objects.filter(pk=pk).update(created_at=created_at)

    def _userdata(self, pk, user, src_name, platform, deleted):
        rel = "%s/%s/%s" % (user.username, platform, src_name)
        self._place(rel, src_name)
        row = UserData(pk=pk, user=user, platform=platform, deleted=deleted)
        row.file.name = rel
        row.save()
        UserData.objects.filter(pk=pk).update(created_at="2020-01-03T00:00:00+00:00")
```

- [ ] **Step 4: Verify the command loads on the old stack**

Run: `docker compose exec web python manage.py help seed_golden`
Expected: prints the command help, no import error.

- [ ] **Step 5: Commit**

```bash
git add app/user_data/management
git commit -m "test: add seed_golden deterministic dataset command"
```

### Task 0.3: Seed the old stack

- [ ] **Step 1: Reset DB to a clean state, migrate, seed**

```bash
docker compose down
docker volume rm data-etipitaka_postgres_data data-etipitaka_media_volume
docker compose up -d
docker compose exec web python manage.py migrate --noinput
docker compose exec web python manage.py seed_golden
```
Expected final line: `seed_golden: done`

- [ ] **Step 2: Verify seed data over HTTP**

Run: `curl -s -H "Authorization: Token a1ce000000000000000000000000000000000001" http://localhost:1338/user_data_list/`
Expected: JSON with an `items` string containing the live UserData row (pk 3001), not the deleted one.

### Task 0.4: Endpoint spec table

**Files:**
- Create: `tests/golden/endpoints.py`

- [ ] **Step 1: Create `tests/golden/endpoints.py`**

```python
"""Golden endpoint case table.

Each GoldenCase issues one HTTP request. Tokens are the fixed keys created by
the seed_golden management command. Mutation cases (POST/DELETE) each act on a
dedicated seed row so a single run stays deterministic.
"""
import io
import json

ALICE_TOKEN = "a1ce000000000000000000000000000000000001"
BOB_TOKEN = "b0b0000000000000000000000000000000000002"

UPLOAD_BODY = json.dumps({"seed": "upload_payload", "version": 1})


class GoldenCase(object):
    def __init__(self, case_id, method, path, token=None, data=None,
                 files=None, allow_redirects=False):
        self.id = case_id
        self.method = method
        self.path = path
        self.token = token
        self.data = data
        self.files = files
        self.allow_redirects = allow_redirects

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
            headers=headers, data=self.data, files=files,
            allow_redirects=self.allow_redirects, timeout=30,
        )


GOLDEN_CASES = [
    # --- public pages ---
    GoldenCase("index_anon", "GET", "/"),
    GoldenCase("login_get", "GET", "/login/"),
    GoldenCase("signup_get", "GET", "/signup/"),
    GoldenCase("validate_get", "GET", "/signup/validate/"),
    GoldenCase("user_data_view_anon", "GET", "/user_data/"),

    # --- auth required, unauthenticated ---
    GoldenCase("sync_data_list_anon", "GET", "/sync_data_list/"),
    GoldenCase("user_data_list_anon", "GET", "/user_data_list/"),

    # --- authenticated reads ---
    GoldenCase("sync_data_list_alice", "GET", "/sync_data_list/", token=ALICE_TOKEN),
    GoldenCase("user_list_alice", "GET", "/user_list/", token=ALICE_TOKEN),
    GoldenCase("sharing_list_alice", "GET", "/sharing_list/", token=ALICE_TOKEN),
    GoldenCase("user_view_bob_by_alice", "GET", "/user/1002/", token=ALICE_TOKEN),
    GoldenCase("user_data_list_alice", "GET", "/user_data_list/", token=ALICE_TOKEN),
    GoldenCase("user_data_list_alice_deleted", "GET", "/user_data_list/?deleted=1", token=ALICE_TOKEN),

    # --- file downloads (body stored as md5 by normalizer) ---
    GoldenCase("download_sync_data_alice", "GET", "/sync_data/sync_alice.json/", token=ALICE_TOKEN),
    GoldenCase("download_sync_data_404", "GET", "/sync_data/nope.json/", token=ALICE_TOKEN),
    GoldenCase("download_user_data_shared", "GET", "/user/1002/sync_alice.json/", token=ALICE_TOKEN),
    GoldenCase("download_user_data_denied", "GET", "/user/9999/sync_alice.json/", token=ALICE_TOKEN),
    GoldenCase("user_data_action_get", "GET", "/user_data/3001/", token=ALICE_TOKEN),
    GoldenCase("user_data_action_get_deleted", "GET", "/user_data/3002/", token=ALICE_TOKEN),

    # --- login form posts ---
    GoldenCase("login_post_invalid", "POST", "/login/",
               data={"username": "alice", "password": "wrongpass"}),

    # --- rest-auth login (token key is the fixed seed value -> deterministic) ---
    GoldenCase("rest_login_alice", "POST", "/rest-auth/login/",
               data={"username": "alice", "password": "alicepass123"}),
    GoldenCase("rest_login_bad", "POST", "/rest-auth/login/",
               data={"username": "alice", "password": "wrongpass"}),

    # --- mutations (each on its own dedicated row / target) ---
    GoldenCase("follower_add", "POST", "/follower/1002/", token=ALICE_TOKEN),
    GoldenCase("follower_remove", "DELETE", "/follower/1002/", token=ALICE_TOKEN),
    GoldenCase("user_data_action_delete", "DELETE", "/user_data/3001/", token=ALICE_TOKEN),
    GoldenCase("upload_view_post", "POST", "/upload/", token=ALICE_TOKEN,
               data={"title": "golden"},
               files={"file": ("upload_payload.json",
                               UPLOAD_BODY.encode("utf-8"), "application/json")}),
    GoldenCase("upload_sync_data_post", "POST", "/sync_data/", token=ALICE_TOKEN,
               data={"platform": "ios", "timestamp": "2020-01-05T00:00:00+00:00"},
               files={"file": ("sync_golden.json",
                               UPLOAD_BODY.encode("utf-8"), "application/json")}),
]
```

> Note: `follower_add` must run before `follower_remove`, and the two `user_data_action` reads before `user_data_action_delete`. `GOLDEN_CASES` list order is the execution order — keep it as written.

- [ ] **Step 2: Commit**

```bash
git add tests/golden/endpoints.py
git commit -m "test: golden endpoint case table"
```

### Task 0.5: Response normalizer

**Files:**
- Create: `tests/golden/normalize.py`
- Test: `tests/golden/test_normalize.py`

- [ ] **Step 1: Write the failing test — `tests/golden/test_normalize.py`**

```python
from normalize import normalize_json_value


def test_timestamp_is_masked():
    value = {"created_at": "2020-01-01T00:00:00Z", "name": "x"}
    assert normalize_json_value(value) == {"created_at": "<TIMESTAMP>", "name": "x"}


def test_nested_timestamp_in_serialized_string_is_masked():
    raw = '[{"fields": {"created_at": "2020-01-01T09:30:00.123Z"}}]'
    out = normalize_json_value({"items": raw})
    assert "<TIMESTAMP>" in out["items"]
    assert "2020-01-01" not in out["items"]
```

- [ ] **Step 2: Run it, verify failure**

Run: `cd tests/golden && python -m pytest test_normalize.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'normalize'`

- [ ] **Step 3: Create `tests/golden/normalize.py`**

```python
import hashlib
import re

VOLATILE_HEADERS = {
    "date", "server", "set-cookie", "vary", "content-length",
    "connection", "keep-alive", "x-frame-options",
}
TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"
)
CSRF_RE = re.compile(r'name="csrfmiddlewaretoken"\s+value="[^"]+"')


def normalize_json_value(value):
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            if key in ("created_at", "created"):
                out[key] = "<TIMESTAMP>"
            else:
                out[key] = normalize_json_value(val)
        return out
    if isinstance(value, list):
        return [normalize_json_value(v) for v in value]
    if isinstance(value, str):
        return TIMESTAMP_RE.sub("<TIMESTAMP>", value)
    return value


def normalize_response(resp):
    headers = {k.lower(): v for k, v in resp.headers.items()
               if k.lower() not in VOLATILE_HEADERS}
    content_type = resp.headers.get("Content-Type", "")
    if "application/json" in content_type:
        body = {"json": normalize_json_value(resp.json())}
    elif "text/html" in content_type:
        stripped = CSRF_RE.sub('name="csrfmiddlewaretoken" value="<CSRF>"', resp.text)
        body = {"html_sha256": hashlib.sha256(stripped.encode("utf-8")).hexdigest()}
    else:
        body = {"body_sha256": hashlib.sha256(resp.content).hexdigest()}
    return {"status": resp.status_code, "headers": headers, "body": body}
```

- [ ] **Step 4: Run the test, verify it passes**

Run: `cd tests/golden && python -m pytest test_normalize.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add tests/golden/normalize.py tests/golden/test_normalize.py
git commit -m "test: golden response normalizer"
```

### Task 0.6: Snapshot store

**Files:**
- Create: `tests/golden/snapshot.py`

- [ ] **Step 1: Create `tests/golden/snapshot.py`**

```python
import json
import os

SNAP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "snapshots")


def _path(case_id):
    return os.path.join(SNAP_DIR, case_id + ".json")


def save_snapshot(case_id, data):
    if not os.path.isdir(SNAP_DIR):
        os.makedirs(SNAP_DIR)
    with open(_path(case_id), "w") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)


def load_snapshot(case_id):
    with open(_path(case_id)) as handle:
        return json.load(handle)
```

- [ ] **Step 2: Commit**

```bash
git add tests/golden/snapshot.py
git commit -m "test: golden snapshot store"
```

### Task 0.7: Parametrized golden test

**Files:**
- Create: `tests/golden/test_golden.py`

- [ ] **Step 1: Create `tests/golden/test_golden.py`**

```python
import pytest

from endpoints import GOLDEN_CASES
from normalize import normalize_response
from snapshot import save_snapshot, load_snapshot


@pytest.mark.parametrize("case", GOLDEN_CASES, ids=[c.id for c in GOLDEN_CASES])
def test_golden(case, http, base_url, record):
    response = case.execute(http, base_url)
    actual = normalize_response(response)
    if record:
        save_snapshot(case.id, actual)
        pytest.skip("recorded snapshot for " + case.id)
    expected = load_snapshot(case.id)
    assert actual == expected, "behavior drift on endpoint case: " + case.id
```

- [ ] **Step 2: Commit**

```bash
git add tests/golden/test_golden.py
git commit -m "test: parametrized golden test"
```

### Task 0.8: Record snapshots against the old app

- [ ] **Step 1: Re-seed the old app** (clean state — Task 0.3 mutations may have run)

```bash
docker compose exec web python manage.py seed_golden
```

- [ ] **Step 2: Record**

```bash
cd tests/golden
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest test_golden.py --record --base-url http://localhost:1338 -v
```
Expected: every case reported `SKIPPED (recorded snapshot ...)`. `tests/golden/snapshots/` now holds one JSON per case.

- [ ] **Step 3: Sanity-check a snapshot**

Run: `cat tests/golden/snapshots/sync_data_list_alice.json`
Expected: `status` 200, `body.json.items` present, no raw timestamps (all `<TIMESTAMP>`).

- [ ] **Step 4: Commit the baseline**

```bash
git add tests/golden/snapshots
git commit -m "test: record golden baseline against Django 1.9 stack"
```

> **Gate:** Phase 0 is complete. The committed snapshots are the regression baseline. Do not change them again — Phase 3 asserts against them.

---

# Phase 1 — Migrate code to Python 3 / Django 5.2

App code changes start here. After Phase 1 the app boots on the new stack but the auth endpoints (`/rest-auth/*`, `/account/*`) are temporarily absent — they return in Phase 2.

### Task 1.1: Rewrite `requirements.txt`

**Files:**
- Modify: `app/requirements.txt`

- [ ] **Step 1: Replace `app/requirements.txt` entirely**

```
Django==5.2.6
djangorestframework==3.16.0
psycopg[binary]==3.2.3
gunicorn==23.0.0
python-dateutil==2.9.0.post0
```

- [ ] **Step 2: Commit**

```bash
git add app/requirements.txt
git commit -m "build: pin Python 3 / Django 5.2 dependencies"
```

### Task 1.2: Rewrite the Dockerfile

**Files:**
- Modify: `app/Dockerfile`

- [ ] **Step 1: Replace `app/Dockerfile` entirely**

```dockerfile
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOME=/home/app
ENV APP_HOME=/home/app/web

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r app && useradd -r -g app app
RUN mkdir -p $APP_HOME/static $APP_HOME/media
WORKDIR $APP_HOME

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . $APP_HOME
RUN chown -R app:app $APP_HOME

USER app
ENTRYPOINT ["/home/app/web/entrypoint.sh"]
```

> `psycopg[binary]` ships compiled wheels, so no build toolchain is needed. `netcat-openbsd` provides the `nc` the entrypoint uses.

- [ ] **Step 2: Commit**

```bash
git add app/Dockerfile
git commit -m "build: Python 3.13-slim base image"
```

### Task 1.3: Clean up `docker-compose.yml`

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Remove the `platform: linux/amd64` line** from the `web` service (added as an arm64 workaround for the Python 2 image; no longer needed). Also remove the obsolete top `version: '3.7'` line.

The `web` service becomes:
```yaml
  web:
    build:
      context: ./app
      dockerfile: Dockerfile
    command: gunicorn etipitaka_auth.wsgi:application --bind 0.0.0.0:8000
    volumes:
      - static_volume:/home/app/web/static
      - media_volume:/home/app/web/media
    expose:
      - 8000
    env_file:
      - ./.env
    depends_on:
      - db
```
And delete the first line `version: '3.7'`.

- [ ] **Step 2: Verify compose still parses**

Run: `docker compose config >/dev/null && echo OK`
Expected: `OK`, no warnings about `version`.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "build: drop amd64 platform pin and obsolete compose version"
```

### Task 1.4: Migrate `models.py`

**Files:**
- Modify: `app/user_data/models.py`

- [ ] **Step 1: Replace `app/user_data/models.py` entirely**

```python
from django.db import models
from django.contrib.auth.models import User


def user_directory_path(instance, filename):
    return '%s/%s/%s' % (instance.user.username, instance.platform, filename)


class UserData(models.Model):
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE)
    platform = models.TextField()
    file = models.FileField(upload_to=user_directory_path)
    deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)


class SyncData(models.Model):
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE)
    name = models.TextField()
    checksum = models.TextField(blank=True, null=True)
    platform = models.TextField()
    file = models.FileField(upload_to=user_directory_path)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)


class Sharing(models.Model):
    owner = models.ForeignKey(User, null=True, related_name='sharing_owners',
                              on_delete=models.CASCADE)
    follower = models.ForeignKey(User, null=True, related_name='sharing_followers',
                                 on_delete=models.CASCADE)
```

> Removed: `from __future__ import unicode_literals` and the unused `from urlparse import urljoin`. `on_delete=models.CASCADE` matches Django 1.9's implicit default and the existing migrations.

- [ ] **Step 2: Verify no new migration is generated** (done after the app boots in Task 1.11) — noted here, checked later.

- [ ] **Step 3: Commit**

```bash
git add app/user_data/models.py
git commit -m "refactor: Python 3 / Django 5.2 compatible models"
```

### Task 1.5: Migrate `settings.py`

**Files:**
- Modify: `app/etipitaka_auth/settings.py`

- [ ] **Step 1: `INSTALLED_APPS`** — replace the block with (allauth/rest_auth removed):

```python
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'user_data',
]
```
> `django.contrib.sites` is also removed — it existed only for allauth.

- [ ] **Step 2: `MIDDLEWARE`** — rename `MIDDLEWARE_CLASSES` to `MIDDLEWARE` and drop the removed `SessionAuthenticationMiddleware`:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

- [ ] **Step 3: `AUTHENTICATION_BACKENDS`** — delete the whole block (the allauth backend is gone; Django's `ModelBackend` default applies).

- [ ] **Step 4: Replace the allauth settings block.** Delete these lines:
```python
SITE_ID = 1
REST_SESSION_LOGIN = True
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_AUTHENTICATION_METHOD = 'username_email'
ACCOUNT_EMAIL_VERIFICATION = 'optional'
ACCOUNT_CONFIRM_EMAIL_ON_GET = True
ACCOUNT_EMAIL_CONFIRMATION_ANONYMOUS_REDIRECT_URL = '/login/?email=confirm'
```
Replace with:
```python
# Email verification (DRF-native rebuild)
EMAIL_VERIFICATION_SALT = 'user-data.email-verify'
EMAIL_VERIFICATION_MAX_AGE = 60 * 60 * 24 * 3  # 3 days
EMAIL_VERIFICATION_URL = '/account/confirm-email/'
```
Keep `DEFAULT_FROM_EMAIL`, `LOGIN_URL`, `LOGIN_REDIRECT_URL`, `EMAIL_BACKEND` as they are.

- [ ] **Step 5: Add `DEFAULT_AUTO_FIELD`** (silences Django 3.2+ warning) — add near `REST_FRAMEWORK`:
```python
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'
```
> `AutoField` (not `BigAutoField`) — the existing tables use 32-bit integer PKs; keep them.

- [ ] **Step 6: Fix the `local_settings` import** at the bottom of the file:
```python
try:
    from .local_settings import *
except ImportError:
    pass
```

- [ ] **Step 7: Commit**

```bash
git add app/etipitaka_auth/settings.py
git commit -m "refactor: Django 5.2 settings, drop allauth/rest-auth"
```

### Task 1.6: Fix the database engine in `local_settings.py`

**Files:**
- Modify: `app/etipitaka_auth/local_settings.py`

- [ ] **Step 1: Change the `ENGINE` line** from `'django.db.backends.postgresql_psycopg2'` to:
```python
        'ENGINE': 'django.db.backends.postgresql',
```
> The `postgresql` backend auto-detects psycopg3.

- [ ] **Step 2: Commit**

```bash
git add app/etipitaka_auth/local_settings.py
git commit -m "refactor: use the postgresql backend (psycopg3)"
```

### Task 1.7: Migrate `urls.py`

**Files:**
- Modify: `app/etipitaka_auth/urls.py`

- [ ] **Step 1: Replace `app/etipitaka_auth/urls.py` entirely**

```python
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import TemplateView

from user_data import views

urlpatterns = [
    path('', views.index_view),
    path('sync_data_list/', views.sync_data_list),
    path('user_list/', views.user_list),
    path('sharing_list/', views.sharing_list),
    path('user/<int:pk>/', views.user),
    re_path(r'^user/(?P<pk>\d+)/(?P<name>.+)/$', views.download_user_data),
    path('sync_data/', views.upload_sync_data),
    re_path(r'^sync_data/(?P<name>.+)/$', views.download_sync_data),
    path('user_data/', views.user_data_view),
    path('user_data_list/', views.user_data_list),
    path('user_data/<int:pk>/', views.user_data_action),
    path('follower/<int:pk>/', views.follower),
    path('upload/', views.upload_view),
    path('login/', views.login_view),
    path('signup/', TemplateView.as_view(template_name="signup.html")),
    path('signup/validate/', TemplateView.as_view(template_name="validate.html")),
    path('admin/', admin.site.urls),
    path('', include('django.contrib.auth.urls')),
]
```
> The `rest-auth`/`account` includes are intentionally absent here — Phase 2 adds them. String view references are replaced with imported callables.

- [ ] **Step 2: Commit**

```bash
git add app/etipitaka_auth/urls.py
git commit -m "refactor: path()-based URLconf, drop allauth includes"
```

### Task 1.8: Migrate `views.py`

**Files:**
- Modify: `app/user_data/views.py`

- [ ] **Step 1: Remove the unused allauth import** — delete line `from allauth.account.decorators import verified_email_required`.

- [ ] **Step 2: Fix `is_authenticated`** in `index_view` — change `if request.user.is_authenticated():` to `if request.user.is_authenticated:` (property, not method, since Django 1.10).

- [ ] **Step 3: Commit**

```bash
git add app/user_data/views.py
git commit -m "refactor: Django 5.2 compatible views"
```

### Task 1.9: Fix templates

**Files:**
- Modify: every `app/templates/**/*.html` that contains `{% load staticfiles %}`

- [ ] **Step 1: Find them**

Run: `grep -rl 'load staticfiles' app/templates`
Expected: a list of template files.

- [ ] **Step 2: In each listed file**, delete the line `{% load staticfiles %}`. Keep the existing `{% load static %}` line (every file that has `staticfiles` also already has `static`). If a file has *only* `staticfiles`, replace it with `{% load static %}`.

- [ ] **Step 3: Verify none remain**

Run: `grep -rl 'load staticfiles' app/templates || echo CLEAN`
Expected: `CLEAN`

- [ ] **Step 4: Commit**

```bash
git add app/templates
git commit -m "refactor: load static (staticfiles tag lib removed in Django 3.0)"
```

### Task 1.10: Boot the new stack and smoke-test

- [ ] **Step 1: Rebuild and start**

```bash
docker compose down
docker volume rm data-etipitaka_postgres_data data-etipitaka_media_volume
docker compose up -d --build
```
Expected: all three containers start. The `postgres_data` volume MUST be removed — the `db` service is now `postgres:16-alpine` and a PG16 server cannot start on the old PG12 data directory. The Phase 0 golden seed is re-created by `seed_golden` in Step 3, so wiping the volume loses nothing needed here.

- [ ] **Step 2: Confirm no model drift**

Run: `docker compose exec web python manage.py makemigrations --check --dry-run`
Expected: `No changes detected`. If a migration is proposed, the `models.py` `on_delete` does not match the migrations — stop and reconcile.

- [ ] **Step 3: Migrate and seed**

```bash
docker compose exec web python manage.py migrate --noinput
docker compose exec web python manage.py seed_golden
```
Expected: `seed_golden: done`

- [ ] **Step 4: Smoke-test non-auth endpoints**

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:1338/
curl -s -H "Authorization: Token a1ce000000000000000000000000000000000001" \
     -o /dev/null -w '%{http_code}\n' http://localhost:1338/user_data_list/
```
Expected: `200` and `200`.

- [ ] **Step 5: Commit** (only if any fixup edits were needed; otherwise skip)

> **Gate:** app boots on Python 3.13 / Django 5.2. Auth endpoints still 404 — Phase 2 next.

---

# Phase 2 — DRF-native auth rebuild

Rebuild `/rest-auth/*` and `/account/confirm-email/*` with plain DRF. Same URL paths, same `name=`s. Registration creates an **inactive** user (mandatory verification).

### Task 2.1: Serializers (TDD)

**Files:**
- Create: `app/user_data/serializers.py`
- Test: `app/user_data/tests/test_serializers.py` (temporary — folded into the Phase 4 suite)

> Phase 4 sets up `pytest-django`. For this task, run the serializer test with Django's runner instead. If `pytest-django` is already configured, use `pytest`.

- [ ] **Step 1: Create `app/user_data/serializers.py`**

```python
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import serializers


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField(max_length=150)
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with that username already exists.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return value

    def validate(self, attrs):
        if attrs['password1'] != attrs['password2']:
            raise serializers.ValidationError({"password": "The two password fields didn't match."})
        return attrs

    def create(self, validated_data):
        user = User(username=validated_data['username'],
                    email=validated_data['email'],
                    is_active=False)
        user.set_password(validated_data['password1'])
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = authenticate(username=attrs['username'], password=attrs['password'])
        if user is None:
            raise serializers.ValidationError(
                {"non_field_errors": ["Unable to log in with provided credentials."]})
        if not user.is_active:
            raise serializers.ValidationError(
                {"non_field_errors": ["This account is not active. Please verify your email."]})
        attrs['user'] = user
        return attrs
```

- [ ] **Step 2: Write the failing test — `app/user_data/tests/test_serializers.py`**

```python
import pytest
from django.contrib.auth.models import User
from user_data.serializers import RegisterSerializer, LoginSerializer

pytestmark = pytest.mark.django_db


def test_register_creates_inactive_user():
    s = RegisterSerializer(data={"email": "n@example.com", "username": "newbie",
                                 "password1": "pw12345678", "password2": "pw12345678"})
    assert s.is_valid(), s.errors
    user = s.save()
    assert user.is_active is False
    assert user.check_password("pw12345678")


def test_register_rejects_password_mismatch():
    s = RegisterSerializer(data={"email": "n@example.com", "username": "newbie",
                                 "password1": "pw12345678", "password2": "different"})
    assert not s.is_valid()
    assert "password" in s.errors


def test_login_rejects_inactive_user():
    u = User(username="ghost", email="g@example.com", is_active=False)
    u.set_password("pw12345678")
    u.save()
    s = LoginSerializer(data={"username": "ghost", "password": "pw12345678"})
    assert not s.is_valid()
```

- [ ] **Step 3: Run it, verify it fails** (no `pytest-django` yet)

Run: `docker compose exec web python -m pytest user_data/tests/test_serializers.py -v` — if this errors on missing `pytest-django`, defer running until Task 4.1, but keep the file.
Expected (once runnable): the three tests are collected.

- [ ] **Step 4: Commit**

```bash
git add app/user_data/serializers.py app/user_data/tests/test_serializers.py
git commit -m "feat: registration and login serializers"
```

### Task 2.2: Email verification template

**Files:**
- Create: `app/templates/email/verify_email.txt`

- [ ] **Step 1: Create `app/templates/email/verify_email.txt`**

```
Hello {{ username }},

Please confirm your E-Tipitaka account email address by visiting the link below:

{{ verify_url }}

This link expires in 3 days. If you did not create this account, ignore this email.

-- E-Tipitaka
```

- [ ] **Step 2: Commit**

```bash
git add app/templates/email/verify_email.txt
git commit -m "feat: email verification message template"
```

### Task 2.3: Auth views

**Files:**
- Create: `app/user_data/auth_views.py`

- [ ] **Step 1: Create `app/user_data/auth_views.py`**

```python
from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.http import HttpResponseRedirect
from django.template.loader import render_to_string

from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .serializers import RegisterSerializer, LoginSerializer


def _signer():
    return TimestampSigner(salt=settings.EMAIL_VERIFICATION_SALT)


def _send_verification_email(request, user):
    token = _signer().sign(str(user.pk))
    verify_url = request.build_absolute_uri(
        settings.EMAIL_VERIFICATION_URL + token + '/')
    body = render_to_string('email/verify_email.txt',
                            {'username': user.username, 'verify_url': verify_url})
    send_mail('Confirm your E-Tipitaka account', body,
              settings.DEFAULT_FROM_EMAIL, [user.email])


def _activate_from_token(token):
    """Return the activated user, or None if the token is invalid/expired."""
    try:
        pk = _signer().unsign(token, max_age=settings.EMAIL_VERIFICATION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    try:
        user = User.objects.get(pk=int(pk))
    except User.DoesNotExist:
        return None
    if not user.is_active:
        user.is_active = True
        user.save(update_fields=['is_active'])
    return user


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def rest_login(request):
    serializer = LoginSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    user = serializer.validated_data['user']
    token, _ = Token.objects.get_or_create(user=user)
    return Response({'key': token.key})


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def rest_logout(request):
    Token.objects.filter(user=request.user).delete()
    return Response({'detail': 'Successfully logged out.'})


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def rest_user_details(request):
    user = request.user
    return Response({'pk': user.pk, 'username': user.username, 'email': user.email})


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def rest_register(request):
    serializer = RegisterSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    user = serializer.save()
    _send_verification_email(request, user)
    return Response({'detail': 'Verification e-mail sent.'},
                    status=status.HTTP_201_CREATED)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def rest_verify_email(request):
    user = _activate_from_token(request.data.get('key', ''))
    if user is None:
        return Response({'detail': 'Invalid or expired token.'},
                        status=status.HTTP_400_BAD_REQUEST)
    return Response({'detail': 'ok'})


@api_view(['GET'])
@authentication_classes([])
@permission_classes([])
def account_confirm_email(request, key):
    """Landing page for the link in the verification email."""
    user = _activate_from_token(key)
    if user is None:
        return HttpResponseRedirect('/login/?email=invalid')
    return HttpResponseRedirect('/login/?email=confirm')
```

- [ ] **Step 2: Commit**

```bash
git add app/user_data/auth_views.py
git commit -m "feat: DRF-native auth views (login, register, verify)"
```

### Task 2.4: Auth URLconf

**Files:**
- Create: `app/user_data/auth_urls.py`
- Modify: `app/etipitaka_auth/urls.py`

- [ ] **Step 1: Create `app/user_data/auth_urls.py`**

```python
from django.urls import path

from . import auth_views

# Mounted under /rest-auth/
rest_auth_patterns = [
    path('login/', auth_views.rest_login, name='rest_login'),
    path('logout/', auth_views.rest_logout, name='rest_logout'),
    path('user/', auth_views.rest_user_details, name='rest_user_details'),
    path('registration/', auth_views.rest_register, name='rest_register'),
    path('registration/verify-email/', auth_views.rest_verify_email,
         name='rest_verify_email'),
]
```

- [ ] **Step 2: Wire it into `app/etipitaka_auth/urls.py`** — add the import and three patterns. The file becomes:

```python
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import TemplateView

from user_data import views, auth_views
from user_data.auth_urls import rest_auth_patterns

urlpatterns = [
    path('', views.index_view),
    path('sync_data_list/', views.sync_data_list),
    path('user_list/', views.user_list),
    path('sharing_list/', views.sharing_list),
    path('user/<int:pk>/', views.user),
    re_path(r'^user/(?P<pk>\d+)/(?P<name>.+)/$', views.download_user_data),
    path('sync_data/', views.upload_sync_data),
    re_path(r'^sync_data/(?P<name>.+)/$', views.download_sync_data),
    path('user_data/', views.user_data_view),
    path('user_data_list/', views.user_data_list),
    path('user_data/<int:pk>/', views.user_data_action),
    path('follower/<int:pk>/', views.follower),
    path('upload/', views.upload_view),
    path('login/', views.login_view),
    path('signup/', TemplateView.as_view(template_name="signup.html")),
    path('signup/validate/', TemplateView.as_view(template_name="validate.html")),
    re_path(r'^account/confirm-email/(?P<key>[^/]+)/$',
            auth_views.account_confirm_email, name='account_confirm_email'),
    path('rest-auth/', include((rest_auth_patterns, 'rest_auth'))),
    path('admin/', admin.site.urls),
    path('', include('django.contrib.auth.urls')),
]
```

- [ ] **Step 3: Verify the URL name resolves** (the signup template needs `rest_register`)

Run: `docker compose exec web python manage.py shell -c "from django.urls import reverse; print(reverse('rest_register'))"`
Expected: `/rest-auth/registration/`

- [ ] **Step 4: Commit**

```bash
git add app/user_data/auth_urls.py app/etipitaka_auth/urls.py
git commit -m "feat: wire DRF auth endpoints at preserved URL paths"
```

### Task 2.5: Filtered seed fixture and `init.sh`

**Files:**
- Create: `app/seed.json`
- Modify: `init.sh`

- [ ] **Step 1: Generate `app/seed.json`** from the current DB, keeping only surviving models

```bash
docker compose exec web python manage.py dumpdata \
    auth.user authtoken.token user_data \
    --indent 2 --output seed.json
docker compose cp data-etipitaka-web-1:/home/app/web/seed.json app/seed.json
```
Expected: `app/seed.json` exists, contains only `auth.user`, `authtoken.token`, `user_data.*` records.

- [ ] **Step 2: Replace `init.sh` entirely**

```sh
#!/bin/sh
docker compose run --rm web python manage.py migrate --noinput
docker compose run --rm web python manage.py collectstatic --noinput
docker compose run --rm web python manage.py loaddata seed.json
```

- [ ] **Step 3: Commit**

```bash
git add app/seed.json init.sh
git commit -m "build: filtered seed fixture and docker-compose init script"
```

### Task 2.6: Boot and smoke-test the auth endpoints

- [ ] **Step 1: Rebuild**

```bash
docker compose up -d --build
docker compose exec web python manage.py seed_golden
```

- [ ] **Step 2: Smoke-test login**

```bash
curl -s -X POST http://localhost:1338/rest-auth/login/ \
     -d 'username=alice&password=alicepass123'
```
Expected: `{"key": "a1ce000000000000000000000000000000000001"}`

- [ ] **Step 3: Smoke-test registration** (uses the console mail backend — see Task 4.1; for now the SMTP backend will error unless mail is configured — verify a 201 with `EMAIL_BACKEND` temporarily set to console if needed)

Run: `curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:1338/rest-auth/registration/ -d 'email=x@example.com&username=xuser&password1=pw12345678&password2=pw12345678'`
Expected: `201`

> **Gate:** all endpoints respond. Phase 3 verifies them against the golden baseline.

---

# Phase 3 — Verify against the golden harness

### Task 3.1: Run the golden harness against the new app

- [ ] **Step 1: Clean state + seed**

```bash
docker compose down
docker volume rm data-etipitaka_postgres_data data-etipitaka_media_volume
docker compose up -d --build
docker compose exec web python manage.py migrate --noinput
docker compose exec web python manage.py seed_golden
```

- [ ] **Step 2: Run the harness in assert mode**

```bash
cd tests/golden && . .venv/bin/activate
python -m pytest test_golden.py -v --base-url http://localhost:1338
```
Expected: all cases PASS.

- [ ] **Step 3: Triage any failure.** For each failing case, diff actual vs `snapshots/<case>.json`. A diff is one of:
  - **A real regression** → fix the app code, re-seed, re-run. Commit the fix.
  - **An intended difference** (only the registration/login-after-signup path is allowed to differ — see Phase 3 Task 3.2) → the case should not have been a golden case; move its assertion to `test_behavioral.py` and delete its snapshot. Document why in the commit message.
  - Do **not** edit a snapshot to make a test pass.

- [ ] **Step 4: Commit any regression fixes**

```bash
git add -A
git commit -m "fix: resolve golden-harness regressions from the migration"
```

### Task 3.2: Behavioral tests for registration / verification

These cannot be byte-matched (tokens are time/secret-based, email is a side effect).

**Files:**
- Create: `tests/golden/test_behavioral.py`

- [ ] **Step 1: Create `tests/golden/test_behavioral.py`**

```python
"""Behavioral assertions for endpoints that cannot be golden-snapshotted.

Registration verification is a deliberate behavior change (mandatory in the
new stack), so these run only against the migrated app.
"""
import uuid


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
```

- [ ] **Step 2: Run it**

Run: `cd tests/golden && . .venv/bin/activate && python -m pytest test_behavioral.py -v --base-url http://localhost:1338`
Expected: 3 passed.

- [ ] **Step 3: Commit**

```bash
git add tests/golden/test_behavioral.py
git commit -m "test: behavioral assertions for registration and verify-email"
```

> **Gate:** golden harness green + behavioral tests green. Migration behavior is verified.

---

# Phase 4 — Django unit tests (new stack)

Full per-function coverage with `pytest` + `pytest-django`, run inside the `web` container.

### Task 4.1: Test tooling setup

**Files:**
- Create: `app/requirements-dev.txt`
- Create: `app/pytest.ini`
- Delete: `app/user_data/tests.py`
- Create: `app/user_data/tests/__init__.py` (empty)

- [ ] **Step 1: Create `app/requirements-dev.txt`**

```
-r requirements.txt
pytest==8.3.4
pytest-django==4.9.0
pytest-cov==6.0.0
```

- [ ] **Step 2: Create `app/pytest.ini`**

```ini
[pytest]
DJANGO_SETTINGS_MODULE = etipitaka_auth.settings
python_files = test_*.py
addopts = --cov=user_data --cov-report=term-missing
```

- [ ] **Step 3: Force the in-memory mail backend during tests.** Add to `app/etipitaka_auth/settings.py`, at the very end of the file (after the `local_settings` import):

```python
import sys
if 'pytest' in sys.modules or 'test' in sys.argv:
    EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
```

- [ ] **Step 4: Remove the placeholder, create the package**

```bash
git rm app/user_data/tests.py
touch app/user_data/tests/__init__.py
```

- [ ] **Step 5: Install dev deps in the running container and verify pytest collects**

```bash
docker compose exec web pip install -r requirements-dev.txt
docker compose exec web python -m pytest user_data/tests/test_serializers.py -v
```
Expected: the 3 serializer tests from Task 2.1 pass.

- [ ] **Step 6: Commit**

```bash
git add app/requirements-dev.txt app/pytest.ini app/etipitaka_auth/settings.py app/user_data/tests/__init__.py
git rm --cached app/user_data/tests.py
git commit -m "test: pytest-django setup with coverage"
```

### Task 4.2: Model tests

**Files:**
- Create: `app/user_data/tests/test_models.py`

- [ ] **Step 1: Create `app/user_data/tests/test_models.py`**

```python
import pytest
from django.contrib.auth.models import User

from user_data.models import UserData, SyncData, Sharing, user_directory_path

pytestmark = pytest.mark.django_db


class _Stub(object):
    def __init__(self, username, platform):
        self.user = type('U', (), {'username': username})()
        self.platform = platform


def test_user_directory_path_builds_username_platform_filename():
    instance = _Stub('alice', 'ios')
    assert user_directory_path(instance, 'data.json') == 'alice/ios/data.json'


def test_userdata_defaults():
    user = User.objects.create_user('u1', 'u1@example.com', 'pw12345678')
    row = UserData.objects.create(user=user, platform='ios', file='u1/ios/a.json')
    assert row.deleted is False
    assert row.created_at is not None


def test_syncdata_checksum_is_optional():
    user = User.objects.create_user('u2', 'u2@example.com', 'pw12345678')
    row = SyncData.objects.create(user=user, name='a.json', platform='ios',
                                  file='u2/ios/a.json')
    assert row.checksum is None


def test_sharing_reverse_accessors():
    owner = User.objects.create_user('owner', 'o@example.com', 'pw12345678')
    follower = User.objects.create_user('follower', 'f@example.com', 'pw12345678')
    Sharing.objects.create(owner=owner, follower=follower)
    assert owner.sharing_owners.count() == 1
    assert follower.sharing_followers.count() == 1
```

- [ ] **Step 2: Run**

Run: `docker compose exec web python -m pytest user_data/tests/test_models.py -v`
Expected: 4 passed.

- [ ] **Step 3: Commit**

```bash
git add app/user_data/tests/test_models.py
git commit -m "test: model unit tests"
```

### Task 4.3: Form tests

**Files:**
- Create: `app/user_data/tests/test_forms.py`

- [ ] **Step 1: Create `app/user_data/tests/test_forms.py`**

```python
from django.core.files.uploadedfile import SimpleUploadedFile

from user_data.forms import UploadFileForm


def test_upload_form_valid():
    upload = SimpleUploadedFile('a.json', b'{}', content_type='application/json')
    form = UploadFileForm(data={'title': 'demo'}, files={'file': upload})
    assert form.is_valid()


def test_upload_form_requires_file():
    form = UploadFileForm(data={'title': 'demo'}, files={})
    assert not form.is_valid()
    assert 'file' in form.errors


def test_upload_form_requires_title():
    upload = SimpleUploadedFile('a.json', b'{}', content_type='application/json')
    form = UploadFileForm(data={}, files={'file': upload})
    assert not form.is_valid()
    assert 'title' in form.errors
```

- [ ] **Step 2: Run**

Run: `docker compose exec web python -m pytest user_data/tests/test_forms.py -v`
Expected: 3 passed.

- [ ] **Step 3: Commit**

```bash
git add app/user_data/tests/test_forms.py
git commit -m "test: UploadFileForm unit tests"
```

### Task 4.4: Data-view tests

Covers all 12 data views in `views.py` and their branches.

**Files:**
- Create: `app/user_data/tests/conftest.py`
- Create: `app/user_data/tests/test_views.py`

- [ ] **Step 1: Create `app/user_data/tests/conftest.py`** (shared fixtures)

```python
import pytest
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from user_data.models import UserData, SyncData, Sharing


@pytest.fixture
def api():
    return APIClient()


@pytest.fixture
def alice(db):
    user = User.objects.create_user('alice', 'alice@example.com', 'alicepass123')
    Token.objects.create(user=user)
    return user


@pytest.fixture
def bob(db):
    user = User.objects.create_user('bob', 'bob@example.com', 'bobpass123')
    Token.objects.create(user=user)
    return user


@pytest.fixture
def auth_alice(api, alice):
    api.credentials(HTTP_AUTHORIZATION='Token ' + alice.auth_token.key)
    return api


def make_syncdata(user, name='s.json', platform='ios'):
    return SyncData.objects.create(user=user, name=name, platform=platform,
                                   file='%s/%s/%s' % (user.username, platform, name))


def make_userdata(user, deleted=False, platform='ios', name='d.json'):
    return UserData.objects.create(user=user, platform=platform, deleted=deleted,
                                   file='%s/%s/%s' % (user.username, platform, name))
```

- [ ] **Step 2: Create `app/user_data/tests/test_views.py`**

```python
import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from user_data.models import UserData, SyncData, Sharing
from user_data.tests.conftest import make_syncdata, make_userdata

pytestmark = pytest.mark.django_db


# --- authentication gate ---

def test_sync_data_list_requires_auth(api):
    assert api.get('/sync_data_list/').status_code in (401, 403)


def test_sync_data_list_authed(auth_alice, alice):
    make_syncdata(alice)
    resp = auth_alice.get('/sync_data_list/')
    assert resp.status_code == 200
    assert 'items' in resp.json()


# --- user / user_list / sharing_list ---

def test_user_returns_target_syncdata(auth_alice, alice, bob):
    make_syncdata(bob)
    resp = auth_alice.get('/user/%d/' % bob.pk)
    assert resp.status_code == 200
    assert 'items' in resp.json()


def test_user_list_returns_followed_owners(auth_alice, alice, bob):
    Sharing.objects.create(owner=bob, follower=alice)
    resp = auth_alice.get('/user_list/')
    assert resp.status_code == 200
    items = resp.json()['items']
    assert any(i['pk'] == bob.pk for i in items)


def test_sharing_list_excludes_self(auth_alice, alice, bob):
    resp = auth_alice.get('/sharing_list/')
    assert resp.status_code == 200
    items = resp.json()['items']
    assert all(i['pk'] != alice.pk for i in items)
    assert any(i['pk'] == bob.pk for i in items)


# --- follower add / remove ---

def test_follower_add(auth_alice, alice, bob):
    resp = auth_alice.post('/follower/%d/' % bob.pk)
    assert resp.status_code == 200
    assert Sharing.objects.filter(owner=alice, follower=bob).count() == 1


def test_follower_add_is_idempotent(auth_alice, alice, bob):
    Sharing.objects.create(owner=alice, follower=bob)
    resp = auth_alice.post('/follower/%d/' % bob.pk)
    assert resp.status_code == 404  # POST when already following -> Http404


def test_follower_remove(auth_alice, alice, bob):
    Sharing.objects.create(owner=alice, follower=bob)
    resp = auth_alice.delete('/follower/%d/' % bob.pk)
    assert resp.status_code == 200
    assert Sharing.objects.filter(owner=alice, follower=bob).count() == 0


# --- download_user_data: sharing access control ---

def test_download_user_data_denied_without_sharing(auth_alice, alice, bob):
    make_syncdata(bob, name='b.json')
    resp = auth_alice.get('/user/%d/b.json/' % bob.pk)
    assert resp.status_code == 404


def test_download_user_data_allowed_with_sharing(auth_alice, alice, bob, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    Sharing.objects.create(owner=bob, follower=alice)
    sd = make_syncdata(bob, name='b.json')
    _write_media(settings.MEDIA_ROOT, sd.file.name, b'{}')
    resp = auth_alice.get('/user/%d/b.json/' % bob.pk)
    assert resp.status_code == 200


# --- download_sync_data ---

def test_download_sync_data_404(auth_alice, alice):
    resp = auth_alice.get('/sync_data/missing.json/')
    assert resp.status_code == 404


def test_download_sync_data_ok(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    sd = make_syncdata(alice, name='s.json')
    _write_media(settings.MEDIA_ROOT, sd.file.name, b'{}')
    resp = auth_alice.get('/sync_data/s.json/')
    assert resp.status_code == 200
    assert resp['Content-Type'] == 'application/etipitaka'


# --- upload_sync_data ---

def test_upload_sync_data_creates_row_and_checksum(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    upload = SimpleUploadedFile('s.json', b'{"v":1}', content_type='application/json')
    resp = auth_alice.post('/sync_data/', {
        'platform': 'ios', 'timestamp': '2020-01-01T00:00:00+00:00', 'file': upload,
    }, format='multipart')
    assert resp.status_code == 200
    body = resp.json()
    assert body['success'] is True
    row = SyncData.objects.get(user=alice, name='s.json')
    assert row.checksum  # md5 was computed


def test_upload_sync_data_no_file_returns_failure(auth_alice, alice):
    resp = auth_alice.post('/sync_data/', {'timestamp': '2020-01-01T00:00:00+00:00'})
    assert resp.status_code == 200
    assert resp.json()['success'] is False


# --- upload_view ---

def test_upload_view_creates_userdata(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    upload = SimpleUploadedFile('d.json', b'{"v":1}', content_type='application/json')
    resp = auth_alice.post('/upload/', {'title': 't', 'file': upload}, format='multipart')
    assert resp.status_code == 200
    assert resp.json()['success'] is True
    assert UserData.objects.filter(user=alice).count() == 1


def test_upload_view_detects_existing_file(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    make_userdata(alice, name='d.json')  # path alice/ios/d.json already present
    upload = SimpleUploadedFile('d.json', b'{"v":1}', content_type='application/json')
    resp = auth_alice.post('/upload/', {'title': 't', 'file': upload}, format='multipart')
    assert resp.status_code == 200
    assert resp.json().get('file_exists') is True


# --- user_data_action: GET / DELETE / soft-delete ---

def test_user_data_action_get_ok(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    ud = make_userdata(alice, name='d.json')
    _write_media(settings.MEDIA_ROOT, ud.file.name, b'{}')
    resp = auth_alice.get('/user_data/%d/' % ud.pk)
    assert resp.status_code == 200


def test_user_data_action_get_deleted_is_404(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    ud = make_userdata(alice, deleted=True, name='d.json')
    _write_media(settings.MEDIA_ROOT, ud.file.name, b'{}')
    resp = auth_alice.get('/user_data/%d/' % ud.pk)
    assert resp.status_code == 404


def test_user_data_action_delete_soft_deletes(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    ud = make_userdata(alice, name='d.json')
    _write_media(settings.MEDIA_ROOT, ud.file.name, b'{}')
    resp = auth_alice.delete('/user_data/%d/' % ud.pk)
    assert resp.status_code == 200
    ud.refresh_from_db()
    assert ud.deleted is True


# --- user_data_list ---

def test_user_data_list_excludes_deleted_by_default(auth_alice, alice):
    make_userdata(alice, deleted=False, name='live.json')
    make_userdata(alice, deleted=True, name='gone.json')
    resp = auth_alice.get('/user_data_list/')
    assert resp.status_code == 200
    assert 'live.json' in resp.json()['items']
    assert 'gone.json' not in resp.json()['items']


def test_user_data_list_deleted_flag(auth_alice, alice):
    make_userdata(alice, deleted=True, name='gone.json')
    resp = auth_alice.get('/user_data_list/?deleted=1')
    assert resp.status_code == 200
    assert 'gone.json' in resp.json()['items']


# --- user_data_view / index_view / login_view ---

def test_user_data_view_redirects_anon(api):
    resp = api.get('/user_data/')
    assert resp.status_code == 302


def test_index_view_anonymous_renders(api):
    resp = api.get('/')
    assert resp.status_code == 200


def test_index_view_authenticated_redirects(auth_alice):
    resp = auth_alice.get('/')
    assert resp.status_code == 302
    assert resp['Location'] == '/user_data/'


def test_login_view_get(api):
    assert api.get('/login/').status_code == 200


def test_login_view_post_valid(api, alice):
    resp = api.post('/login/', {'username': 'alice', 'password': 'alicepass123'})
    assert resp.status_code == 302


def test_login_view_post_invalid(api, alice):
    resp = api.post('/login/', {'username': 'alice', 'password': 'wrong'})
    assert resp.status_code == 200


def _write_media(media_root, rel_name, content):
    import os
    dest = os.path.join(media_root, rel_name)
    parent = os.path.dirname(dest)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    with open(dest, 'wb') as handle:
        handle.write(content)
```

- [ ] **Step 3: Run**

Run: `docker compose exec web python -m pytest user_data/tests/test_views.py -v`
Expected: all tests pass. If a download test fails because `index_view` uses `request.user.is_authenticated`, confirm Task 1.8 Step 2 was applied.

- [ ] **Step 4: Commit**

```bash
git add app/user_data/tests/conftest.py app/user_data/tests/test_views.py
git commit -m "test: data-view unit tests covering all branches"
```

### Task 4.5: Auth-view tests

**Files:**
- Create: `app/user_data/tests/test_auth.py`

- [ ] **Step 1: Create `app/user_data/tests/test_auth.py`**

```python
import pytest
from django.contrib.auth.models import User
from django.core import mail
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from user_data.auth_views import _signer

pytestmark = pytest.mark.django_db


@pytest.fixture
def api():
    return APIClient()


def _register(api, username='newbie', email='n@example.com'):
    return api.post('/rest-auth/registration/', {
        'email': email, 'username': username,
        'password1': 'pw12345678', 'password2': 'pw12345678',
    })


def test_register_creates_inactive_user_and_sends_mail(api):
    resp = _register(api)
    assert resp.status_code == 201
    user = User.objects.get(username='newbie')
    assert user.is_active is False
    assert len(mail.outbox) == 1
    assert 'n@example.com' in mail.outbox[0].to


def test_register_rejects_password_mismatch(api):
    resp = api.post('/rest-auth/registration/', {
        'email': 'n@example.com', 'username': 'newbie',
        'password1': 'pw12345678', 'password2': 'different',
    })
    assert resp.status_code == 400


def test_register_rejects_duplicate_username(api):
    User.objects.create_user('taken', 't@example.com', 'pw12345678')
    resp = _register(api, username='taken', email='other@example.com')
    assert resp.status_code == 400
    assert 'username' in resp.json()


def test_login_returns_token_for_active_user(api):
    user = User.objects.create_user('active', 'a@example.com', 'pw12345678')
    resp = api.post('/rest-auth/login/', {'username': 'active', 'password': 'pw12345678'})
    assert resp.status_code == 200
    assert resp.json()['key'] == Token.objects.get(user=user).key


def test_login_rejected_for_inactive_user(api):
    user = User(username='pending', email='p@example.com', is_active=False)
    user.set_password('pw12345678')
    user.save()
    resp = api.post('/rest-auth/login/', {'username': 'pending', 'password': 'pw12345678'})
    assert resp.status_code == 400


def test_login_rejected_for_bad_password(api):
    User.objects.create_user('active', 'a@example.com', 'pw12345678')
    resp = api.post('/rest-auth/login/', {'username': 'active', 'password': 'wrong'})
    assert resp.status_code == 400


def test_logout_deletes_token(api):
    user = User.objects.create_user('active', 'a@example.com', 'pw12345678')
    token = Token.objects.create(user=user)
    api.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
    resp = api.post('/rest-auth/logout/')
    assert resp.status_code == 200
    assert Token.objects.filter(user=user).count() == 0


def test_user_details(api):
    user = User.objects.create_user('active', 'a@example.com', 'pw12345678')
    token = Token.objects.create(user=user)
    api.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
    resp = api.get('/rest-auth/user/')
    assert resp.status_code == 200
    assert resp.json()['username'] == 'active'


def test_verify_email_activates_account(api):
    user = User(username='pending', email='p@example.com', is_active=False)
    user.set_password('pw12345678')
    user.save()
    token = _signer().sign(str(user.pk))
    resp = api.post('/rest-auth/registration/verify-email/', {'key': token})
    assert resp.status_code == 200
    user.refresh_from_db()
    assert user.is_active is True


def test_verify_email_rejects_bad_token(api):
    resp = api.post('/rest-auth/registration/verify-email/', {'key': 'garbage'})
    assert resp.status_code == 400


def test_confirm_email_link_activates_and_redirects(api):
    user = User(username='pending', email='p@example.com', is_active=False)
    user.set_password('pw12345678')
    user.save()
    token = _signer().sign(str(user.pk))
    resp = api.get('/account/confirm-email/%s/' % token)
    assert resp.status_code == 302
    assert resp['Location'] == '/login/?email=confirm'
    user.refresh_from_db()
    assert user.is_active is True


def test_confirm_email_link_bad_token_redirects_invalid(api):
    resp = api.get('/account/confirm-email/garbage/')
    assert resp.status_code == 302
    assert resp['Location'] == '/login/?email=invalid'
```

- [ ] **Step 2: Run**

Run: `docker compose exec web python -m pytest user_data/tests/test_auth.py -v`
Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add app/user_data/tests/test_auth.py
git commit -m "test: auth-view unit tests"
```

### Task 4.6: Full suite + coverage gate

- [ ] **Step 1: Run the whole suite with coverage**

Run: `docker compose exec web python -m pytest`
Expected: all tests pass; the coverage table prints. Every function in `user_data/views.py`, `models.py`, `forms.py`, `serializers.py`, `auth_views.py` appears covered.

- [ ] **Step 2: Inspect `--cov-report=term-missing`.** For any uncovered line, add a targeted test in the matching `test_*.py` file, commit, and re-run. Target: 100% of functions, ≥90% of lines.

- [ ] **Step 3: Add the line-coverage floor to `app/pytest.ini`** once met:

```ini
addopts = --cov=user_data --cov-report=term-missing --cov-fail-under=90
```

- [ ] **Step 4: Commit**

```bash
git add app/pytest.ini
git commit -m "test: enforce 90% line-coverage floor"
```

> **Gate:** full unit suite green, coverage floor enforced.

---

# Phase 5 — Deployment & CI

### Task 5.1: GitHub Actions workflow

**Files:**
- Create: `.env.ci`, `.env.db.ci` (non-secret env files for CI)
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create non-secret CI env files.** The real `.env` / `.env.db` hold secrets and are not committed, so CI needs its own. Create `.env.ci`:

```
DEBUG=1
SQL_ENGINE=django.db.backends.postgresql
SQL_DATABASE=etipitaka_data
SQL_USER=etipitaka
SQL_PASSWORD=cipass
SQL_HOST=db
SQL_PORT=5432
DATABASE=postgres
```

Create `.env.db.ci`:
```
POSTGRES_DB=etipitaka_data
POSTGRES_USER=etipitaka
POSTGRES_PASSWORD=cipass
```

- [ ] **Step 2: Create `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_DB: etipitaka_data
          POSTGRES_USER: etipitaka
          POSTGRES_PASSWORD: testpass
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    env:
      SQL_ENGINE: django.db.backends.postgresql
      SQL_DATABASE: etipitaka_data
      SQL_USER: etipitaka
      SQL_PASSWORD: testpass
      SQL_HOST: localhost
      SQL_PORT: 5432
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.13'
      - name: Install dependencies
        run: pip install -r app/requirements-dev.txt
      - name: Run unit tests with coverage
        working-directory: app
        run: python -m pytest

  golden-harness:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start the stack
        run: |
          cp .env.ci .env
          cp .env.db.ci .env.db
          docker compose up -d --build
      - name: Wait for the app
        run: |
          docker compose exec -T web python manage.py migrate --noinput
          for i in $(seq 1 30); do
            if curl -sf http://localhost:1338/ >/dev/null; then exit 0; fi
            sleep 2
          done
          echo "app did not come up"; docker compose logs; exit 1
      - name: Seed and run the golden harness
        run: |
          docker compose exec -T web python manage.py seed_golden
          pip install -r tests/golden/requirements.txt
          python -m pytest tests/golden -v --base-url http://localhost:1338
```

> Note: the `unit-tests` job reads DB config from `SQL_*` env vars. This works only if `local_settings.py` reads those env vars. If `local_settings.py` hardcodes the database (it currently does), add a Step 2 below.

- [ ] **Step 2: Make `local_settings.py` env-aware** so CI can point it at its own Postgres. Replace the `DATABASES` block in `app/etipitaka_auth/local_settings.py` with:

```python
import os

DATABASES = {
    'default': {
        'ENGINE': os.environ.get('SQL_ENGINE', 'django.db.backends.postgresql'),
        'NAME': os.environ.get('SQL_DATABASE', 'etipitaka_data'),
        'USER': os.environ.get('SQL_USER', 'etipitaka'),
        'PASSWORD': os.environ.get('SQL_PASSWORD', 'u2-*^We#9aP'),
        'HOST': os.environ.get('SQL_HOST', 'db'),
        'PORT': os.environ.get('SQL_PORT', '5432'),
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml app/etipitaka_auth/local_settings.py .env.ci .env.db.ci
git commit -m "ci: GitHub Actions running unit + golden suites"
```

### Task 5.2: Update `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the Development Stack section of `CLAUDE.md`** to reflect the new reality:

```markdown
## Development Stack
1. Django 5.2 LTS web framework (Python 3.13)
2. Django REST Framework for the API
3. PostgreSQL via psycopg3
4. Docker Compose for local dev and deployment

## Testing
- Unit tests: `docker compose exec web python -m pytest` (pytest-django, coverage-gated)
- Golden harness: see `tests/golden/README.md` — cross-stack HTTP regression suite
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for the Django 5.2 stack"
```

### Task 5.3: Production PostgreSQL 12 → 16 upgrade runbook

Django 5.2 requires PostgreSQL 14+. Production currently runs PG12. A PG16 server will not start on a PG12 data directory, so the production database must be upgraded as part of cutover. This task produces the runbook; the actual upgrade is run by whoever operates production, during the maintenance window.

**Files:**
- Create: `docs/runbooks/postgres-12-to-16-upgrade.md`

- [ ] **Step 1: Write `docs/runbooks/postgres-12-to-16-upgrade.md`** documenting the dump/restore upgrade path (simplest and safest for a database this small):

```markdown
# Production PostgreSQL 12 → 16 upgrade

Required before the Django 5.2 release can be deployed — Django 5.2 refuses
to connect to PostgreSQL < 14.

## Preconditions
- Maintenance window (the app is offline during the upgrade).
- Verified, restorable backup of the PG12 database.

## Procedure (dump / restore)

1. Stop the application containers (leave `db` running):
   `docker compose stop web nginx`

2. Dump the PG12 database:
   `docker compose exec db pg_dump -U etipitaka -Fc etipitaka_data > etipitaka_data.dump`

3. Stop and remove the PG12 container and its volume:
   `docker compose stop db`
   `docker compose rm -f db`
   `docker volume rm data-etipitaka_postgres_data`

4. Pull the new image and start a fresh PG16 instance:
   `docker compose up -d db`
   (compose now pins `postgres:16-alpine`; the empty volume initialises a PG16 cluster.)

5. Restore the dump into PG16:
   `cat etipitaka_data.dump | docker compose exec -T db pg_restore -U etipitaka -d etipitaka_data --clean --if-exists`

6. Start the app and run migrations:
   `docker compose up -d web nginx`
   `docker compose exec web python manage.py migrate --noinput`

7. Smoke-test, then delete `etipitaka_data.dump`.

## Rollback
If restore fails, recreate the PG12 container (temporarily repin `postgres:12.0-alpine`)
and restore the dump there; the application stays on the old release until resolved.
```

- [ ] **Step 2: Commit**

```bash
git add docs/runbooks/postgres-12-to-16-upgrade.md
git commit -m "docs: production Postgres 12 to 16 upgrade runbook"
```

> **Gate:** CI green on both jobs; production upgrade runbook written. Migration complete.

---

## Final verification checklist

- [ ] `docker compose up -d --build` starts all three containers (db on `postgres:16-alpine`)
- [ ] `docker compose exec web python manage.py makemigrations --check --dry-run` → `No changes detected`
- [ ] `pytest tests/golden` green against the new app (matches the Phase 0 baseline)
- [ ] `pytest tests/golden/test_behavioral.py` green
- [ ] `docker compose exec web python -m pytest` green, coverage ≥ 90%
- [ ] CI workflow green on both jobs
- [ ] Production cutover: PG12→PG16 upgrade per `docs/runbooks/postgres-12-to-16-upgrade.md`, then deploy; old `allauth`/`socialaccount` tables remain as harmless orphans

## Out of scope (follow-up tasks)
- Dropping the orphaned `allauth_*` / `socialaccount_*` tables via a cleanup migration
- Moving `SECRET_KEY` / email credentials out of source into environment variables
