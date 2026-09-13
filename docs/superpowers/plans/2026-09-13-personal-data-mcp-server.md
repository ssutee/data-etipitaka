# Personal Data MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose a user's personal E-Tipitaka study data and the Buddhist canon (search, passage read, dictionaries, cross-reference) to AI agents through an MCP server.

**Architecture:** Two phases. Phase 1 adds read-only Django REST endpoints that open a user's per-platform SQLite sync DBs and return normalized JSON — independently shippable. Phase 2 builds a local stdio MCP server that (a) calls those endpoints for personal data using a web-credential→token exchange, and (b) reads the local canon/dictionary SQLite files directly for search, passage read, dictionary lookup, and `code`→edition cross-reference.

**Tech Stack:** Django 5.2 + DRF (Python 3.13), pytest/pytest-django, golden HTTP harness, Docker Compose; MCP server in Python with the `mcp` SDK (FastMCP) + `httpx`, tested with pytest.

**Spec:** `docs/superpowers/specs/2026-09-13-personal-data-mcp-server-design.md`

**Conventions:**
- Run Django tests in Docker: `docker compose exec web python -m pytest <path> -v`.
  If `pytest` is missing in the container, first run
  `docker compose exec --user root web pip install -r requirements-dev.txt`.
- App test fixtures live in `app/user_data/tests/conftest.py`
  (`api`, `alice`, `bob`, `auth_alice`, `make_syncdata`, `make_userdata`).
- MCP server tests run in its own venv: `cd mcp_server && pytest -v`.

---

## File Structure

**Phase 1 — Django (in `app/`):**
- Create `app/user_data/sqlite_reader.py` — the only module that opens a user's SQLite files; reflect columns, normalize timestamps, read-only.
- Create `app/user_data/content_views.py` — six read-only DRF endpoints.
- Modify `app/etipitaka_auth/urls.py` — mount `/api/content/*`.
- Modify `app/user_data/tests/conftest.py` — add `media_tmp` fixture + `make_content_db` helper.
- Create `app/user_data/tests/test_sqlite_reader.py`, `app/user_data/tests/test_content_views.py`.
- Modify `app/user_data/management/commands/seed_golden.py`, `tests/golden/endpoints.py`; add snapshots.

**Phase 2 — MCP server (new top-level `mcp_server/`):**
- `mcp_server/pyproject.toml`
- `mcp_server/etipitaka_mcp/__init__.py`
- `mcp_server/etipitaka_mcp/config.py` — env config.
- `mcp_server/etipitaka_mcp/auth.py` — token mint/cache.
- `mcp_server/etipitaka_mcp/client.py` — httpx personal-data client.
- `mcp_server/etipitaka_mcp/canon_registry.py` — edition/code/dictionary registry.
- `mcp_server/etipitaka_mcp/canon_reader.py` — local canon/dictionary reader.
- `mcp_server/etipitaka_mcp/server.py` — FastMCP app + tools + `main()`.
- `mcp_server/tests/*` — pytest suites.
- `mcp_server/README.md` — install + client config.

---

# Phase 1 — Django Content REST API

## Task 1: `sqlite_reader` helper

**Files:**
- Create: `app/user_data/sqlite_reader.py`
- Modify: `app/user_data/tests/conftest.py`
- Test: `app/user_data/tests/test_sqlite_reader.py`

- [ ] **Step 1: Add test helpers to conftest**

Append to `app/user_data/tests/conftest.py`:

```python
import os
import sqlite3


@pytest.fixture
def media_tmp(settings, tmp_path):
    """Redirect MEDIA_ROOT to a temp dir so content DBs never touch app/media."""
    settings.MEDIA_ROOT = str(tmp_path)
    return tmp_path


def make_content_db(user, filename, table, schema_sql, rows, platform='ios'):
    """Create a SyncData row backed by a real SQLite file under MEDIA_ROOT."""
    from django.conf import settings
    rel = '%s/%s/%s' % (user.username, platform, filename)
    dest = os.path.join(settings.MEDIA_ROOT, rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    conn = sqlite3.connect(dest)
    conn.execute(schema_sql)
    if rows:
        placeholders = ','.join('?' * len(rows[0]))
        conn.executemany('INSERT INTO %s VALUES (%s)' % (table, placeholders), rows)
    conn.commit()
    conn.close()
    sd = SyncData(user=user, name=filename, platform=platform)
    sd.file.name = rel
    sd.save()
    return sd
```

- [ ] **Step 2: Write the failing test**

Create `app/user_data/tests/test_sqlite_reader.py`:

```python
import pytest

from user_data.sqlite_reader import read_table
from user_data.tests.conftest import make_content_db

pytestmark = pytest.mark.django_db

BOOKMARK_SCHEMA = ("CREATE TABLE bookmark (created FLOAT, important INTEGER, "
                   "note TEXT, rank INTEGER, code INTEGER, volume INTEGER, page INTEGER)")


def test_reads_rows_and_tags_platform(media_tmp, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(1457843335.09, 1, 'ธรรมอันเลิศ', 0, 1, 10, 101)])
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert total == 1
    assert rows[0]['note'] == 'ธรรมอันเลิศ'
    assert rows[0]['platform'] == 'ios'


def test_normalizes_created_timestamp(media_tmp, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(1457843335.09, 0, '', 0, 1, 10, 101)])
    rows, _ = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert rows[0]['created'].startswith('2016-03-13')


def test_missing_file_and_missing_table_return_empty(media_tmp, alice):
    # SyncData row whose file never gets created
    from user_data.models import SyncData
    sd = SyncData(user=alice, name='bookmark.sqlite', platform='ios')
    sd.file.name = 'alice/ios/bookmark.sqlite'
    sd.save()
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert (rows, total) == ([], 0)


def test_filters_search_and_pagination(media_tmp, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA, [
        (0, 1, 'alpha', 0, 1, 10, 1),
        (0, 0, 'beta', 0, 1, 11, 2),
        (0, 1, 'gamma note', 0, 2, 12, 3),
    ])
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark',
                             filters={'code': '1'})
    assert total == 2
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark',
                             search=(['note'], 'note'))
    assert total == 1 and rows[0]['note'] == 'gamma note'
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark',
                             limit=1, offset=1)
    assert total == 3 and len(rows) == 1


def test_own_data_only(media_tmp, alice, bob):
    make_content_db(bob, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 1, 'bobmark', 0, 1, 1, 1)])
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert (rows, total) == ([], 0)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `docker compose exec web python -m pytest user_data/tests/test_sqlite_reader.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'user_data.sqlite_reader'`.

- [ ] **Step 4: Implement `sqlite_reader.py`**

Create `app/user_data/sqlite_reader.py`:

```python
import os
import sqlite3
from datetime import datetime, timezone

# Columns holding a Unix-epoch float we normalize to ISO-8601.
_TIMESTAMP_COLUMNS = {'created'}


def _iso(value):
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return value


def _open_ro(path):
    return sqlite3.connect('file:%s?mode=ro&immutable=1' % path, uri=True)


def _table_exists(conn, table):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _build_where(filters, search):
    clauses, params = [], []
    for col, val in (filters or {}).items():
        clauses.append('%s = ?' % col)
        params.append(val)
    if search:
        cols, term = search
        clauses.append('(%s)' % ' OR '.join('%s LIKE ?' % c for c in cols))
        params.extend(['%' + term + '%'] * len(cols))
    if not clauses:
        return '', []
    return ' WHERE ' + ' AND '.join(clauses), params


def read_table(user, db_filename, table, *, filters=None, search=None,
               platform=None, limit=50, offset=0):
    """Read `table` from each of `user`'s `db_filename` SyncData files.

    Returns (rows, total). Rows are dicts tagged with 'platform'. Timestamp
    columns are normalized to ISO-8601. Missing files, missing tables and
    corrupt databases are skipped. Only the calling user's rows are ever read.
    """
    qs = user.syncdata_set.filter(name=db_filename)
    if platform:
        qs = qs.filter(platform=platform)

    where_sql, where_params = _build_where(filters, search)
    all_rows, total = [], 0
    for sd in qs:
        path = sd.file.path
        if not os.path.exists(path):
            continue
        try:
            conn = _open_ro(path)
        except sqlite3.Error:
            continue
        try:
            if not _table_exists(conn, table):
                continue
            total += conn.execute(
                'SELECT COUNT(*) FROM %s%s' % (table, where_sql), where_params
            ).fetchone()[0]
            cur = conn.execute('SELECT * FROM %s%s' % (table, where_sql), where_params)
            cols = [c[0] for c in cur.description]
            ts_cols = _TIMESTAMP_COLUMNS & set(cols)
            for raw in cur.fetchall():
                row = dict(zip(cols, raw))
                for tc in ts_cols:
                    row[tc] = _iso(row[tc])
                row['platform'] = sd.platform
                all_rows.append(row)
        except sqlite3.DatabaseError:
            continue
        finally:
            conn.close()

    return all_rows[offset:offset + limit], total
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec web python -m pytest user_data/tests/test_sqlite_reader.py -v`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add app/user_data/sqlite_reader.py app/user_data/tests/test_sqlite_reader.py app/user_data/tests/conftest.py
git commit -m "feat: add read-only sqlite_reader for user content DBs"
```

---

## Task 2: `bookmarks` and `highlights` endpoints

**Files:**
- Create: `app/user_data/content_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_content_views.py`

- [ ] **Step 1: Write the failing test**

Create `app/user_data/tests/test_content_views.py`:

```python
import pytest

from user_data.tests.conftest import make_content_db

pytestmark = pytest.mark.django_db

BOOKMARK_SCHEMA = ("CREATE TABLE bookmark (created FLOAT, important INTEGER, "
                   "note TEXT, rank INTEGER, code INTEGER, volume INTEGER, page INTEGER)")
HIGHLIGHT_SCHEMA = ("CREATE TABLE highlight (selection TEXT, type INTEGER, note TEXT, "
                    "start INTEGER, end INTEGER, volume INTEGER, page INTEGER, "
                    "code INTEGER, position INTEGER)")


def test_bookmarks_requires_auth(api):
    assert api.get('/api/content/bookmarks/').status_code in (401, 403)


def test_bookmarks_returns_rows(media_tmp, auth_alice, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 1, 'ธรรม', 0, 1, 10, 101)])
    resp = auth_alice.get('/api/content/bookmarks/')
    assert resp.status_code == 200
    body = resp.json()
    assert body['count'] == 1
    assert body['items'][0]['note'] == 'ธรรม'
    assert body['limit'] == 50 and body['offset'] == 0


def test_bookmarks_volume_filter_and_note_search(media_tmp, auth_alice, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA, [
        (0, 1, 'first', 0, 1, 10, 1),
        (0, 0, 'second', 0, 1, 11, 2),
    ])
    assert auth_alice.get('/api/content/bookmarks/?volume=11').json()['count'] == 1
    assert auth_alice.get('/api/content/bookmarks/?q=first').json()['count'] == 1


def test_bookmarks_limit_clamped(media_tmp, auth_alice, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 0, 'x', 0, 1, 1, 1)])
    body = auth_alice.get('/api/content/bookmarks/?limit=9999').json()
    assert body['limit'] == 500


def test_bookmarks_own_data_only(media_tmp, auth_alice, alice, bob):
    make_content_db(bob, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 1, 'bob', 0, 1, 1, 1)])
    assert auth_alice.get('/api/content/bookmarks/').json()['count'] == 0


def test_highlights_search_selection(media_tmp, auth_alice, alice):
    make_content_db(alice, 'highlight.sqlite', 'highlight', HIGHLIGHT_SCHEMA,
                    [('อาสีวิสสูตร', 1, '', 0, 0, 21, 110, 1, 1)])
    body = auth_alice.get('/api/content/highlights/?q=อาสีวิส').json()
    assert body['count'] == 1
    assert body['items'][0]['selection'] == 'อาสีวิสสูตร'
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec web python -m pytest user_data/tests/test_content_views.py -v`
Expected: FAIL — 404 (routes not wired) / import error.

- [ ] **Step 3: Implement `content_views.py`**

Create `app/user_data/content_views.py`:

```python
from django.http import JsonResponse
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes)
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from .sqlite_reader import read_table

DEFAULT_LIMIT = 50
MAX_LIMIT = 500

DB_TABLES = {
    'bookmarks':  ('bookmark.sqlite', 'bookmark'),
    'highlights': ('highlight.sqlite', 'highlight'),
    'tags':       ('tag.sqlite', 'tag'),
    'history':    ('history.sqlite', 'history'),
    'lexicon':    ('saved_lexicon.sqlite', 'lexicon'),
}


def _int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _paging(request):
    limit = max(1, min(_int(request.GET.get('limit'), DEFAULT_LIMIT), MAX_LIMIT))
    offset = max(0, _int(request.GET.get('offset'), 0))
    return limit, offset


def _filters(request, allowed):
    out = {}
    for param, col in allowed.items():
        val = request.GET.get(param)
        if val not in (None, ''):
            out[col] = val
    return out


def _list(request, db_filename, table, *, allowed, search_cols):
    limit, offset = _paging(request)
    platform = request.GET.get('platform') or None
    filters = _filters(request, allowed)
    q = request.GET.get('q')
    search = (search_cols, q) if q else None
    rows, total = read_table(request.user, db_filename, table, filters=filters,
                             search=search, platform=platform,
                             limit=limit, offset=offset)
    return JsonResponse({'items': rows, 'count': total,
                         'limit': limit, 'offset': offset})


def _content_endpoint(allowed, search_cols, key):
    db_filename, table = DB_TABLES[key]

    @api_view(['GET'])
    @authentication_classes((TokenAuthentication, SessionAuthentication))
    @permission_classes((IsAuthenticated,))
    def view(request):
        return _list(request, db_filename, table,
                     allowed=allowed, search_cols=search_cols)
    return view


bookmarks = _content_endpoint(
    {'code': 'code', 'volume': 'volume', 'page': 'page', 'important': 'important'},
    ['note'], 'bookmarks')

highlights = _content_endpoint(
    {'code': 'code', 'volume': 'volume', 'page': 'page'},
    ['selection', 'note'], 'highlights')
```

- [ ] **Step 4: Wire the URLs**

In `app/etipitaka_auth/urls.py`, add the import alongside the existing `from user_data import ...`:

```python
from user_data import content_views
```

and add these entries to `urlpatterns` (place them just before the `rest-auth/` include):

```python
    path('api/content/bookmarks/', content_views.bookmarks),
    path('api/content/highlights/', content_views.highlights),
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec web python -m pytest user_data/tests/test_content_views.py -v`
Expected: PASS (6 tests).

- [ ] **Step 6: Commit**

```bash
git add app/user_data/content_views.py app/etipitaka_auth/urls.py app/user_data/tests/test_content_views.py
git commit -m "feat: add bookmarks + highlights content endpoints"
```

---

## Task 3: `tags`, `history`, `lexicon` endpoints

**Files:**
- Modify: `app/user_data/content_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_content_views.py`

- [ ] **Step 1: Write the failing tests**

Append to `app/user_data/tests/test_content_views.py`:

```python
TAG_SCHEMA = ("CREATE TABLE tag (name TEXT, history TEXT, note TEXT, "
              "highlight TEXT, priority INTEGER, code INTEGER)")
HISTORY_SCHEMA = ("CREATE TABLE history (keywords TEXT, created FLOAT, detail TEXT, "
                  "code INTEGER, starred INTEGER, state INTEGER, read TEXT, "
                  "skimmed TEXT, items TEXT, marked TEXT, type INTEGER, note TEXT, "
                  "buddhawaj BOOLEAN, note_items TEXT, note_state INTEGER, priority INTEGER)")
LEXICON_SCHEMA = "CREATE TABLE lexicon (type INTEGER, head TEXT, translation TEXT)"


def test_tags_name_search(media_tmp, auth_alice, alice):
    make_content_db(alice, 'tag.sqlite', 'tag', TAG_SCHEMA,
                    [('ขันธ์', '', '', '', 0, 1), ('ธาตุ', '', '', '', 0, 1)])
    assert auth_alice.get('/api/content/tags/?q=ขันธ์').json()['count'] == 1
    assert auth_alice.get('/api/content/tags/').json()['count'] == 2


def test_history_starred_filter(media_tmp, auth_alice, alice):
    row = ('อานาปานสติ', 0.0, '', 1, 1, 0, '', '', '', '', 1, '', 1, '', 0, 0)
    row2 = ('เวทนา', 0.0, '', 1, 0, 0, '', '', '', '', 1, '', 1, '', 0, 0)
    make_content_db(alice, 'history.sqlite', 'history', HISTORY_SCHEMA, [row, row2])
    assert auth_alice.get('/api/content/history/?starred=1').json()['count'] == 1
    assert auth_alice.get('/api/content/history/?q=อานา').json()['count'] == 1


def test_lexicon_head_search(media_tmp, auth_alice, alice):
    make_content_db(alice, 'saved_lexicon.sqlite', 'lexicon', LEXICON_SCHEMA,
                    [(1, 'ภว', 'ความมี, ความเป็น')])
    body = auth_alice.get('/api/content/lexicon/?q=ภว').json()
    assert body['count'] == 1 and body['items'][0]['translation'].startswith('ความ')
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec web python -m pytest user_data/tests/test_content_views.py -k "tags or history or lexicon" -v`
Expected: FAIL — 404 (routes not wired).

- [ ] **Step 3: Add the endpoints**

Append to `app/user_data/content_views.py`:

```python
tags = _content_endpoint({}, ['name'], 'tags')

history = _content_endpoint({'starred': 'starred'}, ['keywords'], 'history')

lexicon = _content_endpoint({}, ['head'], 'lexicon')
```

- [ ] **Step 4: Wire the URLs**

Add to `urlpatterns` in `app/etipitaka_auth/urls.py` (next to the other content routes):

```python
    path('api/content/tags/', content_views.tags),
    path('api/content/history/', content_views.history),
    path('api/content/lexicon/', content_views.lexicon),
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec web python -m pytest user_data/tests/test_content_views.py -k "tags or history or lexicon" -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add app/user_data/content_views.py app/etipitaka_auth/urls.py app/user_data/tests/test_content_views.py
git commit -m "feat: add tags, history, lexicon content endpoints"
```

---

## Task 4: `summary` endpoint

**Files:**
- Modify: `app/user_data/content_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_content_views.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_content_views.py`:

```python
def test_summary_counts_per_type_and_platform(media_tmp, auth_alice, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 1, 'a', 0, 1, 1, 1)], platform='ios')
    make_content_db(alice, 'tag.sqlite', 'tag', TAG_SCHEMA,
                    [('ขันธ์', '', '', '', 0, 1)], platform='ios')
    body = auth_alice.get('/api/content/summary/').json()
    assert body['username'] == 'alice'
    assert body['platforms'] == ['ios']
    assert body['counts']['bookmarks'] == {'ios': 1}
    assert body['counts']['tags'] == {'ios': 1}
    assert body['counts']['highlights'] == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose exec web python -m pytest user_data/tests/test_content_views.py::test_summary_counts_per_type_and_platform -v`
Expected: FAIL — 404.

- [ ] **Step 3: Implement `summary`**

Append to `app/user_data/content_views.py`:

```python
@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication))
@permission_classes((IsAuthenticated,))
def summary(request):
    counts, platforms = {}, set()
    for key, (db_filename, table) in DB_TABLES.items():
        rows, _ = read_table(request.user, db_filename, table,
                             limit=10 ** 9, offset=0)
        per = {}
        for row in rows:
            p = row['platform']
            per[p] = per.get(p, 0) + 1
            platforms.add(p)
        counts[key] = per
    return JsonResponse({'username': request.user.username,
                         'platforms': sorted(platforms), 'counts': counts})
```

- [ ] **Step 4: Wire the URL**

Add to `urlpatterns` in `app/etipitaka_auth/urls.py`:

```python
    path('api/content/summary/', content_views.summary),
```

- [ ] **Step 5: Run test to verify it passes**

Run: `docker compose exec web python -m pytest user_data/tests/test_content_views.py -v`
Expected: PASS (all content-view tests).

- [ ] **Step 6: Run full suite + coverage gate**

Run: `docker compose exec web python -m pytest`
Expected: PASS, coverage ≥ 90%.

- [ ] **Step 7: Commit**

```bash
git add app/user_data/content_views.py app/etipitaka_auth/urls.py app/user_data/tests/test_content_views.py
git commit -m "feat: add content summary endpoint"
```

---

## Task 5: Golden-harness snapshots for content endpoints

Content endpoints are new and same-stack only (the old stack lacks them) — this mirrors the localization note already in `tests/golden/README.md`.

**Files:**
- Modify: `app/user_data/management/commands/seed_golden.py`
- Modify: `tests/golden/endpoints.py`
- Modify: `tests/golden/README.md`
- Create: snapshot files under `tests/golden/snapshots/` (recorded, not hand-written)

- [ ] **Step 1: Seed a deterministic bookmark DB for alice**

In `app/user_data/management/commands/seed_golden.py`, add near the top:

```python
import sqlite3
```

Add this method to `Command`:

```python
    def _content_db(self, pk, user, filename, table, schema_sql, rows, platform='ios'):
        rel = '%s/%s/%s' % (user.username, platform, filename)
        dest = os.path.join(settings.MEDIA_ROOT, rel)
        parent = os.path.dirname(dest)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        conn = sqlite3.connect(dest)
        conn.execute(schema_sql)
        placeholders = ','.join('?' * len(rows[0]))
        conn.executemany('INSERT INTO %s VALUES (%s)' % (table, placeholders), rows)
        conn.commit()
        conn.close()
        row = SyncData(pk=pk, user=user, name=filename, platform=platform,
                       checksum='seedchecksum')
        row.file.name = rel
        row.save()
        SyncData.objects.filter(pk=pk).update(created_at='2020-01-04T00:00:00+00:00')
```

In `handle()`, after the existing alice sync/user data, add:

```python
        self._content_db(
            2101, alice, 'bookmark.sqlite', 'bookmark',
            "CREATE TABLE bookmark (created FLOAT, important INTEGER, note TEXT, "
            "rank INTEGER, code INTEGER, volume INTEGER, page INTEGER)",
            [(1457843335.0, 1, 'golden-note', 0, 1, 10, 101)])
```

- [ ] **Step 2: Add golden cases**

In `tests/golden/endpoints.py`, add to `GOLDEN_CASES` (after the authenticated reads):

```python
    # --- content API (same-stack; old stack lacks these routes) ---
    GoldenCase("content_bookmarks_alice", "GET", "/api/content/bookmarks/", token=ALICE_TOKEN),
    GoldenCase("content_bookmarks_anon", "GET", "/api/content/bookmarks/"),
    GoldenCase("content_summary_alice", "GET", "/api/content/summary/", token=ALICE_TOKEN),
```

- [ ] **Step 3: Document the same-stack additions**

In `tests/golden/README.md`, under the "Localization note" list, add a bullet:

```markdown
- The `/api/content/*` snapshots (`content_bookmarks_alice`,
  `content_bookmarks_anon`, `content_summary_alice`) are same-stack — these
  routes did not exist on the old stack.
```

- [ ] **Step 4: Record the snapshots**

```bash
docker compose up -d
docker compose exec web python manage.py seed_golden
. tests/golden/.venv/bin/activate 2>/dev/null || (python3 -m venv tests/golden/.venv && . tests/golden/.venv/bin/activate && pip install -r tests/golden/requirements.txt)
pytest tests/golden/test_golden.py -k content --record --base-url http://localhost:1338
```

Expected: three new files in `tests/golden/snapshots/` (`content_bookmarks_alice.json`, `content_bookmarks_anon.json`, `content_summary_alice.json`).

- [ ] **Step 5: Assert they pass on replay**

Run: `pytest tests/golden -k content -v --base-url http://localhost:1338`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/management/commands/seed_golden.py tests/golden/endpoints.py tests/golden/README.md tests/golden/snapshots/content_*.json
git commit -m "test: golden snapshots for content API endpoints"
```

---

# Phase 2 — MCP Server

## Task 6: MCP project scaffold + config

**Files:**
- Create: `mcp_server/pyproject.toml`, `mcp_server/etipitaka_mcp/__init__.py`, `mcp_server/etipitaka_mcp/config.py`
- Test: `mcp_server/tests/test_config.py`

- [ ] **Step 1: Create `pyproject.toml`**

Create `mcp_server/pyproject.toml`:

```toml
[project]
name = "etipitaka-mcp"
version = "0.1.0"
description = "MCP server exposing E-Tipitaka personal data and canon search."
requires-python = ">=3.11"
dependencies = ["mcp>=1.2.0", "httpx>=0.27"]

[project.optional-dependencies]
keyring = ["keyring>=25"]
dev = ["pytest>=8", "pytest-httpx>=0.30"]

[project.scripts]
etipitaka-mcp = "etipitaka_mcp.server:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

- [ ] **Step 2: Create the package + write the failing test**

Create `mcp_server/etipitaka_mcp/__init__.py` (empty). Create `mcp_server/tests/test_config.py`:

```python
from etipitaka_mcp.config import load_config


def test_defaults(monkeypatch):
    for var in ['ETIPITAKA_BASE_URL', 'ETIPITAKA_USERNAME', 'ETIPITAKA_PASSWORD',
                'ETIPITAKA_TOKEN', 'ETIPITAKA_RESOURCES_DIR', 'ETIPITAKA_DEFAULT_EDITION']:
        monkeypatch.delenv(var, raising=False)
    cfg = load_config()
    assert cfg.base_url == 'https://data.etipitaka.com'
    assert cfg.username is None and cfg.token is None
    assert cfg.resources_dir is None


def test_reads_env(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_BASE_URL', 'http://localhost:1338')
    monkeypatch.setenv('ETIPITAKA_USERNAME', 'alice')
    monkeypatch.setenv('ETIPITAKA_DEFAULT_EDITION', 'thaiwn')
    cfg = load_config()
    assert cfg.base_url == 'http://localhost:1338'
    assert cfg.username == 'alice'
    assert cfg.default_edition == 'thaiwn'
```

- [ ] **Step 3: Set up the venv and run the test (expect fail)**

```bash
cd mcp_server && python3 -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
pytest tests/test_config.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'etipitaka_mcp.config'`.

- [ ] **Step 4: Implement `config.py`**

Create `mcp_server/etipitaka_mcp/config.py`:

```python
import os
from dataclasses import dataclass


@dataclass
class Config:
    base_url: str
    username: str | None
    password: str | None
    token: str | None
    resources_dir: str | None
    default_edition: str | None


def load_config():
    return Config(
        base_url=os.environ.get('ETIPITAKA_BASE_URL', 'https://data.etipitaka.com'),
        username=os.environ.get('ETIPITAKA_USERNAME'),
        password=os.environ.get('ETIPITAKA_PASSWORD'),
        token=os.environ.get('ETIPITAKA_TOKEN'),
        resources_dir=os.environ.get('ETIPITAKA_RESOURCES_DIR'),
        default_edition=os.environ.get('ETIPITAKA_DEFAULT_EDITION'),
    )
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_config.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add mcp_server/pyproject.toml mcp_server/etipitaka_mcp/__init__.py mcp_server/etipitaka_mcp/config.py mcp_server/tests/test_config.py
git commit -m "feat(mcp): scaffold etipitaka-mcp package + config"
```

---

## Task 7: Token authenticator

**Files:**
- Create: `mcp_server/etipitaka_mcp/auth.py`
- Test: `mcp_server/tests/test_auth.py`

- [ ] **Step 1: Write the failing test**

Create `mcp_server/tests/test_auth.py`:

```python
import stat

import pytest

from etipitaka_mcp.auth import Authenticator, AuthError


def test_uses_explicit_token_without_login(tmp_path):
    auth = Authenticator('http://x', token='TOK', cache_path=tmp_path / 't')
    assert auth.token() == 'TOK'


def test_mints_from_credentials(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/rest-auth/login/', json={'key': 'MINTED'})
    auth = Authenticator('http://x', username='alice', password='pw',
                         cache_path=tmp_path / 't')
    assert auth.token() == 'MINTED'


def test_caches_token_0600(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/rest-auth/login/', json={'key': 'MINTED'})
    cache = tmp_path / 'sub' / 't'
    auth = Authenticator('http://x', username='alice', password='pw', cache_path=cache)
    auth.token()
    assert cache.read_text() == 'MINTED'
    assert stat.S_IMODE(cache.stat().st_mode) == 0o600


def test_reuses_cached_token(tmp_path):
    cache = tmp_path / 't'
    cache.write_text('CACHED')
    auth = Authenticator('http://x', username='alice', password='pw', cache_path=cache)
    assert auth.token() == 'CACHED'


def test_refresh_remints(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/rest-auth/login/', json={'key': 'FRESH'})
    cache = tmp_path / 't'
    cache.write_text('STALE')
    auth = Authenticator('http://x', username='alice', password='pw', cache_path=cache)
    assert auth.token(refresh=True) == 'FRESH'
    assert cache.read_text() == 'FRESH'


def test_no_credentials_raises(tmp_path):
    auth = Authenticator('http://x', cache_path=tmp_path / 't')
    with pytest.raises(AuthError):
        auth.token()


def test_login_failure_raises(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/rest-auth/login/', status_code=400,
                            json={'non_field_errors': ['bad']})
    auth = Authenticator('http://x', username='a', password='b', cache_path=tmp_path / 't')
    with pytest.raises(AuthError):
        auth.token()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_auth.py -v`
Expected: FAIL — no module `etipitaka_mcp.auth`.

- [ ] **Step 3: Implement `auth.py`**

Create `mcp_server/etipitaka_mcp/auth.py`:

```python
import os
import stat
from pathlib import Path

import httpx


class AuthError(Exception):
    pass


class Authenticator:
    """Obtains and caches a DRF token, minting from web credentials once."""

    def __init__(self, base_url, username=None, password=None, token=None,
                 cache_path=None, timeout=30):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self._explicit_token = token
        self.timeout = timeout
        self.cache_path = Path(cache_path) if cache_path else (
            Path.home() / '.config' / 'etipitaka-mcp' / 'token')

    def _read_cache(self):
        try:
            return self.cache_path.read_text().strip() or None
        except OSError:
            return None

    def _write_cache(self, token):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(token)
        os.chmod(self.cache_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    def _mint(self):
        if self._explicit_token:
            return self._explicit_token
        if not (self.username and self.password):
            raise AuthError('no credentials: set ETIPITAKA_TOKEN or '
                            'ETIPITAKA_USERNAME + ETIPITAKA_PASSWORD')
        try:
            resp = httpx.post(self.base_url + '/rest-auth/login/',
                              data={'username': self.username,
                                    'password': self.password},
                              timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise AuthError('login request failed: %s' % exc)
        if resp.status_code != 200:
            raise AuthError('login failed (HTTP %s)' % resp.status_code)
        return resp.json()['key']

    def token(self, *, refresh=False):
        if not refresh:
            cached = self._read_cache()
            if cached:
                return cached
        token = self._mint()
        self._write_cache(token)
        return token
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_auth.py -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add mcp_server/etipitaka_mcp/auth.py mcp_server/tests/test_auth.py
git commit -m "feat(mcp): token authenticator with credential exchange + cache"
```

---

## Task 8: Personal-data HTTP client

**Files:**
- Create: `mcp_server/etipitaka_mcp/client.py`
- Test: `mcp_server/tests/test_client.py`

- [ ] **Step 1: Write the failing test**

Create `mcp_server/tests/test_client.py`:

```python
from etipitaka_mcp.auth import Authenticator
from etipitaka_mcp.client import ContentClient


def _auth(tmp_path, token='TOK'):
    return Authenticator('http://x', token=token, cache_path=tmp_path / 't')


def test_get_sends_token_and_drops_none_params(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/api/content/bookmarks/?volume=10',
                            json={'items': [], 'count': 0})
    client = ContentClient(_auth(tmp_path))
    client.list_bookmarks(volume=10, code=None)
    req = httpx_mock.get_requests()[0]
    assert req.headers['Authorization'] == 'Token TOK'
    assert b'code' not in req.url.query


def test_refreshes_once_on_401(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/api/content/summary/', status_code=401)
    httpx_mock.add_response(url='http://x/rest-auth/login/', json={'key': 'FRESH'})
    httpx_mock.add_response(url='http://x/api/content/summary/', json={'ok': True})
    auth = Authenticator('http://x', username='a', password='b',
                         cache_path=tmp_path / 't')
    auth._write_cache('STALE')
    assert ContentClient(auth).get_summary() == {'ok': True}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_client.py -v`
Expected: FAIL — no module `etipitaka_mcp.client`.

- [ ] **Step 3: Implement `client.py`**

Create `mcp_server/etipitaka_mcp/client.py`:

```python
import httpx


class ContentClient:
    """Calls the Django Content REST API, attaching the auth token."""

    def __init__(self, auth, timeout=30):
        self.auth = auth
        self.timeout = timeout

    def _get(self, path, params=None):
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        url = self.auth.base_url + path
        token = self.auth.token()
        resp = httpx.get(url, params=clean,
                         headers={'Authorization': 'Token %s' % token},
                         timeout=self.timeout)
        if resp.status_code == 401:
            token = self.auth.token(refresh=True)
            resp = httpx.get(url, params=clean,
                             headers={'Authorization': 'Token %s' % token},
                             timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def list_bookmarks(self, **params):
        return self._get('/api/content/bookmarks/', params)

    def list_highlights(self, **params):
        return self._get('/api/content/highlights/', params)

    def list_tags(self, **params):
        return self._get('/api/content/tags/', params)

    def list_history(self, **params):
        return self._get('/api/content/history/', params)

    def list_lexicon(self, **params):
        return self._get('/api/content/lexicon/', params)

    def get_summary(self):
        return self._get('/api/content/summary/')

    def whoami(self):
        return self._get('/rest-auth/user/')
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_client.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add mcp_server/etipitaka_mcp/client.py mcp_server/tests/test_client.py
git commit -m "feat(mcp): personal-data HTTP client with 401 refresh"
```

---

## Task 9: Canon registry

**Files:**
- Create: `mcp_server/etipitaka_mcp/canon_registry.py`
- Test: `mcp_server/tests/test_canon_registry.py`

- [ ] **Step 1: Write the failing test**

Create `mcp_server/tests/test_canon_registry.py`:

```python
import pytest

from etipitaka_mcp import canon_registry as reg


def test_edition_for_ios_and_android():
    assert reg.edition_for('ios', 1) == 'thai'
    assert reg.edition_for('ios', 6) == 'thaiwn'
    assert reg.edition_for('android', 0) == 'thai'


def test_edition_for_unknown_platform_or_code():
    with pytest.raises(reg.RegistryError):
        reg.edition_for('pc', 1)
    with pytest.raises(reg.RegistryError):
        reg.edition_for('ios', 999)


def test_edition_path_missing_file(tmp_path):
    with pytest.raises(reg.RegistryError):
        reg.edition_path(str(tmp_path), 'thai')


def test_edition_path_present(tmp_path):
    (tmp_path / 'thai.sqlite').write_text('x')
    assert reg.edition_path(str(tmp_path), 'thai').endswith('thai.sqlite')


def test_dictionary_metadata():
    assert reg.DICTIONARIES['pali_thai']['table'] == 'p2t'
    assert reg.DICTIONARIES['pali_thai']['head'] == 'headword'
    assert reg.DICTIONARIES['thai']['head'] == 'head'


@pytest.mark.skipif(
    not __import__('os').path.exists(
        '/Users/sutee/Works/watnapahpong/E-Tipitaka-PC/constants.py'),
    reason='PC app constants.py not present')
def test_code_tables_match_pc_app():
    import importlib.util
    path = '/Users/sutee/Works/watnapahpong/E-Tipitaka-PC/constants.py'
    spec = importlib.util.spec_from_file_location('pc_constants', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert reg.IOS_CODE_TABLE == mod.IOS_CODE_TABLE
    assert reg.ANDROID_CODE_TABLE == mod.ANDROID_CODE_TABLE
    assert set(reg.EDITIONS) >= set(mod.CODES)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_canon_registry.py -v`
Expected: FAIL — no module `etipitaka_mcp.canon_registry`.

- [ ] **Step 3: Implement `canon_registry.py`**

Create `mcp_server/etipitaka_mcp/canon_registry.py`:

```python
import os

# Edition key -> file + display name. Copied from E-Tipitaka-PC constants.py
# (the *_DB constants and LANGS); the PC app is intentionally NOT imported.
EDITIONS = {
    'thai':    {'filename': 'thai.sqlite',    'name': 'ไทย (ฉบับหลวง)'},
    'pali':    {'filename': 'pali.sqlite',    'name': 'บาลี (สยามรัฐ)'},
    'palinew': {'filename': 'palinew.sqlite', 'name': 'บาลี (สยามรัฐ ฉบับใหม่)'},
    'palimc':  {'filename': 'palimc.sqlite',  'name': 'บาลี (มหาจุฬาฯ)'},
    'thaimm':  {'filename': 'thaimm.sqlite',  'name': 'ไทย (มหามกุฏฯ)'},
    'thaimc':  {'filename': 'thaimc.sqlite',  'name': 'ไทย (มหาจุฬาฯ ๑)'},
    'thaimc2': {'filename': 'thaimc2.sqlite', 'name': 'ไทย (มหาจุฬาฯ ๒)'},
    'thaibt':  {'filename': 'thaibt.sqlite',  'name': 'พุทธวจน (ชุดจากพระโอษฐ์)'},
    'thaipb':  {'filename': 'thaipb.sqlite',  'name': 'ไทย (ฉบับพกพา)'},
    'thaims':  {'filename': 'thaims.sqlite',  'name': 'ไทย (เฉลิมพระเกียรติ ๒๕๔๙)'},
    'thaivn':  {'filename': 'thaivn.sqlite',  'name': 'อริยวินัย'},
    'thaiwn':  {'filename': 'thaiwn.sqlite',  'name': 'พุทธวจน (วัดนาป่าพง)'},
    'thaict':  {'filename': 'thaict.sqlite',  'name': 'ไทย (อักษรไทย)'},
    'romanct': {'filename': 'romanct.sqlite', 'name': 'Roman Script'},
}

# Integer code -> edition key, per client platform (from constants.py).
IOS_CODE_TABLE = {1: 'thai', 2: 'pali', 3: 'thaimm', 4: 'thaimc', 5: 'thaibt',
                  6: 'thaiwn', 7: 'thaipb', 8: 'romanct', 9: 'palimc',
                  10: 'thaims', 11: 'thaivn', 12: 'thaimc2'}
ANDROID_CODE_TABLE = {0: 'thai', 1: 'pali', 2: 'thaimm', 3: 'thaimc', 4: 'thaibt',
                      5: 'thaiwn', 6: 'thaipb', 7: 'romanct', 8: 'palimc',
                      9: 'thaivn'}

DICTIONARIES = {
    'pali_thai': {'filename': 'p2t_dict.sqlite', 'table': 'p2t',
                  'head': 'headword',
                  'columns': ['headword', 'content', 'type', 'gender', 'vachana',
                              'viphat', 'category', 'read', 'note', 'roman',
                              'eng_content', 'source']},
    'pali_english': {'filename': 'pali-english.sqlite', 'table': 'english',
                     'head': 'head', 'columns': ['head', 'translation']},
    'thai': {'filename': 'thaidict.sqlite', 'table': 'thai',
             'head': 'head', 'columns': ['head', 'translation']},
}


class RegistryError(Exception):
    pass


def edition_for(platform, code):
    table = {'ios': IOS_CODE_TABLE, 'android': ANDROID_CODE_TABLE}.get(platform)
    if table is None:
        raise RegistryError('code resolution unsupported for platform %r' % platform)
    try:
        return table[int(code)]
    except (KeyError, ValueError, TypeError):
        raise RegistryError('unknown code %r for platform %s' % (code, platform))


def edition_path(resources_dir, edition_key):
    meta = EDITIONS.get(edition_key)
    if not meta:
        raise RegistryError('unknown edition: %r' % edition_key)
    path = os.path.join(resources_dir, meta['filename'])
    if not os.path.exists(path):
        raise RegistryError('edition file not found: %s' % path)
    return path


def dictionary_path(resources_dir, dictionary_key):
    meta = DICTIONARIES.get(dictionary_key)
    if not meta:
        raise RegistryError('unknown dictionary: %r' % dictionary_key)
    path = os.path.join(resources_dir, meta['filename'])
    if not os.path.exists(path):
        raise RegistryError('dictionary file not found: %s' % path)
    return path
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_canon_registry.py -v`
Expected: PASS (drift test runs if the PC app is present, else skipped).

- [ ] **Step 5: Commit**

```bash
git add mcp_server/etipitaka_mcp/canon_registry.py mcp_server/tests/test_canon_registry.py
git commit -m "feat(mcp): canon edition/code/dictionary registry"
```

---

## Task 10: Canon reader

**Files:**
- Create: `mcp_server/etipitaka_mcp/canon_reader.py`
- Test: `mcp_server/tests/test_canon_reader.py`

- [ ] **Step 1: Write the failing test**

Create `mcp_server/tests/test_canon_reader.py`:

```python
import sqlite3

import pytest

from etipitaka_mcp import canon_reader
from etipitaka_mcp import canon_registry as reg


@pytest.fixture
def resources(tmp_path):
    conn = sqlite3.connect(str(tmp_path / 'thai.sqlite'))
    conn.execute('CREATE TABLE main (volume VARCHAR(2), page VARCHAR(4), '
                 'items VARCHAR(100), content TEXT)')
    conn.executemany('INSERT INTO main VALUES (?,?,?,?)', [
        ('01', '0001', '1', 'พระวินัยปิฎก มหาวิภังค์'),
        ('10', '0101', '1', 'ธรรมอันเลิศ ย่อมมี'),
        ('10', '0102', '2', 'อีกหน้าหนึ่ง'),
    ])
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(tmp_path / 'p2t_dict.sqlite'))
    conn.execute('CREATE TABLE p2t (headword text, content text, type text, '
                 'gender text, vachana text, viphat text, category text, '
                 'read text, note text, roman text, eng_content text, source text)')
    conn.execute("INSERT INTO p2t VALUES ('ภว','ความมี','','','','','','','','bhava','','')")
    conn.commit()
    conn.close()
    return str(tmp_path)


def test_search_matches_and_snippets(resources):
    items, total = canon_reader.search(resources, 'thai', 'ธรรมอันเลิศ')
    assert total == 1
    assert items[0]['volume'] == '10' and items[0]['page'] == '0101'
    assert 'ธรรมอันเลิศ' in items[0]['snippet']


def test_search_volume_filter_and_pagination(resources):
    _, total = canon_reader.search(resources, 'thai', 'หน้า', volume=10)
    assert total == 1
    items, total = canon_reader.search(resources, 'thai', '', limit=1, offset=1)
    assert total == 3 and len(items) == 1


def test_get_page_pads_volume_and_page(resources):
    row = canon_reader.get_page(resources, 'thai', 10, 101)
    assert row['content'] == 'ธรรมอันเลิศ ย่อมมี'


def test_get_page_missing_returns_none(resources):
    assert canon_reader.get_page(resources, 'thai', 99, 9999) is None


def test_search_missing_edition_raises(resources):
    with pytest.raises(reg.RegistryError):
        canon_reader.search(resources, 'thaiwn', 'x')


def test_lookup_exact_prefix_contains(resources):
    assert canon_reader.lookup(resources, 'pali_thai', 'ภว')[0]['content'] == 'ความมี'
    assert canon_reader.lookup(resources, 'pali_thai', 'ภ', match='prefix')
    assert canon_reader.lookup(resources, 'pali_thai', 'ว', match='contains')
    assert canon_reader.lookup(resources, 'pali_thai', 'zzz') == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_canon_reader.py -v`
Expected: FAIL — no module `etipitaka_mcp.canon_reader`.

- [ ] **Step 3: Implement `canon_reader.py`**

Create `mcp_server/etipitaka_mcp/canon_reader.py`:

```python
import sqlite3

from . import canon_registry as reg


class CanonError(Exception):
    pass


def _open_ro(path):
    return sqlite3.connect('file:%s?mode=ro&immutable=1' % path, uri=True)


def _snippet(content, term, width=80):
    if not term:
        return content[:width]
    idx = content.lower().find(term.lower())
    if idx < 0:
        return content[:width]
    start = max(0, idx - width // 2)
    end = min(len(content), idx + len(term) + width // 2)
    return ('…' if start else '') + content[start:end] + ('…' if end < len(content) else '')


def search(resources_dir, edition_key, query, *, volume=None, limit=20, offset=0):
    path = reg.edition_path(resources_dir, edition_key)  # raises RegistryError if missing
    where, params = 'content LIKE ?', ['%' + query + '%']
    if volume is not None:
        where += ' AND volume = ?'
        params.append('%02d' % int(volume))
    conn = _open_ro(path)
    try:
        total = conn.execute('SELECT COUNT(*) FROM main WHERE ' + where,
                             params).fetchone()[0]
        cur = conn.execute(
            'SELECT volume, page, items, content FROM main WHERE ' + where
            + ' ORDER BY volume, page LIMIT ? OFFSET ?', params + [limit, offset])
        items = [{'edition': edition_key, 'volume': v, 'page': p, 'items': it,
                  'snippet': _snippet(c or '', query)}
                 for (v, p, it, c) in cur.fetchall()]
        return items, total
    finally:
        conn.close()


def get_page(resources_dir, edition_key, volume, page):
    path = reg.edition_path(resources_dir, edition_key)
    conn = _open_ro(path)
    try:
        sql = 'SELECT volume, page, items, content FROM main WHERE volume=? AND page=?'
        row = conn.execute(sql, ('%02d' % int(volume), '%04d' % int(page))).fetchone()
        if row is None:  # unpadded fallback for editions that store raw values
            row = conn.execute(sql, (str(volume), str(page))).fetchone()
        if row is None:
            return None
        return {'edition': edition_key, 'volume': row[0], 'page': row[1],
                'items': row[2], 'content': row[3]}
    finally:
        conn.close()


def lookup(resources_dir, dictionary_key, term, *, match='exact', limit=20):
    meta = reg.DICTIONARIES.get(dictionary_key)
    if not meta:
        raise CanonError('unknown dictionary: %r' % dictionary_key)
    path = reg.dictionary_path(resources_dir, dictionary_key)
    head, table, cols = meta['head'], meta['table'], meta['columns']
    if match == 'exact':
        clause, param = head + ' = ?', term
    elif match == 'prefix':
        clause, param = head + ' LIKE ?', term + '%'
    elif match == 'contains':
        clause, param = head + ' LIKE ?', '%' + term + '%'
    else:
        raise CanonError('bad match mode: %r' % match)
    conn = _open_ro(path)
    try:
        cur = conn.execute(
            'SELECT %s FROM %s WHERE %s LIMIT ?' % (','.join(cols), table, clause),
            (param, limit))
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_canon_reader.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add mcp_server/etipitaka_mcp/canon_reader.py mcp_server/tests/test_canon_reader.py
git commit -m "feat(mcp): local canon + dictionary reader"
```

---

## Task 11: FastMCP server + tools

**Files:**
- Create: `mcp_server/etipitaka_mcp/server.py`
- Test: `mcp_server/tests/test_server.py`

- [ ] **Step 1: Write the failing test**

Create `mcp_server/tests/test_server.py`. These tests exercise the tool
implementation functions directly (the FastMCP wrappers call them).

```python
import sqlite3

import pytest


@pytest.fixture
def server(tmp_path, monkeypatch):
    # canon fixture
    conn = sqlite3.connect(str(tmp_path / 'thai.sqlite'))
    conn.execute('CREATE TABLE main (volume VARCHAR(2), page VARCHAR(4), '
                 'items VARCHAR(100), content TEXT)')
    conn.execute("INSERT INTO main VALUES ('10','0101','1','ธรรมอันเลิศ')")
    conn.commit()
    conn.close()
    monkeypatch.setenv('ETIPITAKA_RESOURCES_DIR', str(tmp_path))
    monkeypatch.setenv('ETIPITAKA_DEFAULT_EDITION', 'thai')
    monkeypatch.setenv('ETIPITAKA_TOKEN', 'TOK')
    import importlib
    import etipitaka_mcp.server as srv
    return importlib.reload(srv)


def test_search_canon_uses_default_edition(server):
    out = server._search_canon('ธรรมอันเลิศ')
    assert out['count'] == 1 and out['items'][0]['page'] == '0101'


def test_get_passage(server):
    assert server._get_passage('thai', 10, 101)['content'] == 'ธรรมอันเลิศ'


def test_resolve_reference_ios(server):
    # ios code 1 -> 'thai'
    assert server._resolve_reference('ios', 1, 10, 101)['content'] == 'ธรรมอันเลิศ'


def test_list_editions_marks_present(server):
    eds = {e['key']: e for e in server._list_editions()['editions']}
    assert eds['thai']['present'] is True
    assert eds['thaiwn']['present'] is False


def test_canon_requires_resources_dir(tmp_path, monkeypatch):
    monkeypatch.delenv('ETIPITAKA_RESOURCES_DIR', raising=False)
    monkeypatch.setenv('ETIPITAKA_TOKEN', 'TOK')
    import importlib
    import etipitaka_mcp.server as srv
    srv = importlib.reload(srv)
    with pytest.raises(ValueError):
        srv._search_canon('x')
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_server.py -v`
Expected: FAIL — no module `etipitaka_mcp.server`.

- [ ] **Step 3: Implement `server.py`**

Create `mcp_server/etipitaka_mcp/server.py`. Each tool is a thin FastMCP
wrapper over a plain `_impl` function (the tests call the `_impl` functions).

```python
import os

from mcp.server.fastmcp import FastMCP

from . import canon_reader
from . import canon_registry as reg
from .auth import Authenticator
from .client import ContentClient
from .config import load_config

cfg = load_config()
mcp = FastMCP('etipitaka')

_auth = Authenticator(cfg.base_url, cfg.username, cfg.password, cfg.token)
_content = ContentClient(_auth)


def _require_resources():
    if not cfg.resources_dir or not os.path.isdir(cfg.resources_dir):
        raise ValueError('canon unavailable: set ETIPITAKA_RESOURCES_DIR '
                         'to the E-Tipitaka resources folder')
    return cfg.resources_dir


# --- personal data (plain impls) ---
def _list_bookmarks(**kw): return _content.list_bookmarks(**kw)
def _list_highlights(**kw): return _content.list_highlights(**kw)
def _list_tags(**kw): return _content.list_tags(**kw)
def _list_history(**kw): return _content.list_history(**kw)
def _list_lexicon(**kw): return _content.list_lexicon(**kw)
def _get_summary(): return _content.get_summary()
def _whoami(): return _content.whoami()


# --- canon (plain impls) ---
def _search_canon(query, edition=None, volume=None, limit=20, offset=0):
    rdir = _require_resources()
    edition = edition or cfg.default_edition
    if not edition:
        raise ValueError('no edition given and ETIPITAKA_DEFAULT_EDITION unset')
    items, total = canon_reader.search(rdir, edition, query, volume=volume,
                                       limit=limit, offset=offset)
    return {'items': items, 'count': total, 'limit': limit, 'offset': offset}


def _get_passage(edition, volume, page):
    rdir = _require_resources()
    row = canon_reader.get_page(rdir, edition, volume, page)
    if row is None:
        raise ValueError('passage not found: %s vol %s page %s'
                         % (edition, volume, page))
    return row


def _resolve_reference(platform, code, volume, page):
    rdir = _require_resources()
    edition = reg.edition_for(platform, code)
    row = canon_reader.get_page(rdir, edition, volume, page)
    if row is None:
        raise ValueError('passage not found for %s code %s vol %s page %s'
                         % (platform, code, volume, page))
    return row


def _list_editions():
    rdir = cfg.resources_dir
    editions = [{'key': k, 'name': m['name'],
                 'present': bool(rdir) and os.path.exists(os.path.join(rdir, m['filename']))}
                for k, m in reg.EDITIONS.items()]
    return {'editions': editions, 'dictionaries': list(reg.DICTIONARIES),
            'default_edition': cfg.default_edition}


def _lookup_dictionary(term, dictionary='pali_thai', match='exact', limit=20):
    rdir = _require_resources()
    entries = canon_reader.lookup(rdir, dictionary, term, match=match, limit=limit)
    return {'entries': entries, 'count': len(entries)}


# --- MCP tool registrations ---
@mcp.tool()
def list_bookmarks(platform: str | None = None, code: int | None = None,
                   volume: int | None = None, page: int | None = None,
                   important: int | None = None, query: str | None = None,
                   limit: int = 50, offset: int = 0) -> dict:
    """List the user's bookmarks (canon locations with notes)."""
    return _list_bookmarks(platform=platform, code=code, volume=volume, page=page,
                           important=important, q=query, limit=limit, offset=offset)


@mcp.tool()
def list_highlights(platform: str | None = None, code: int | None = None,
                    volume: int | None = None, page: int | None = None,
                    query: str | None = None, limit: int = 50, offset: int = 0) -> dict:
    """List the user's highlighted passages (selected text + notes)."""
    return _list_highlights(platform=platform, code=code, volume=volume, page=page,
                            q=query, limit=limit, offset=offset)


@mcp.tool()
def list_tags(platform: str | None = None, query: str | None = None,
              limit: int = 50, offset: int = 0) -> dict:
    """List the user's tags."""
    return _list_tags(platform=platform, q=query, limit=limit, offset=offset)


@mcp.tool()
def list_history(platform: str | None = None, starred: int | None = None,
                 query: str | None = None, limit: int = 50, offset: int = 0) -> dict:
    """List the user's search/reading history."""
    return _list_history(platform=platform, starred=starred, q=query,
                         limit=limit, offset=offset)


@mcp.tool()
def list_lexicon(platform: str | None = None, query: str | None = None,
                 limit: int = 50, offset: int = 0) -> dict:
    """List the user's saved dictionary (lexicon) terms."""
    return _list_lexicon(platform=platform, q=query, limit=limit, offset=offset)


@mcp.tool()
def get_summary() -> dict:
    """Per-type, per-platform counts of the user's data."""
    return _get_summary()


@mcp.tool()
def whoami() -> dict:
    """The authenticated user's pk, username, email."""
    return _whoami()


@mcp.tool()
def list_editions() -> dict:
    """Available canon editions (key, name, present) and dictionary keys."""
    return _list_editions()


@mcp.tool()
def search_canon(query: str, edition: str | None = None, volume: int | None = None,
                 limit: int = 20, offset: int = 0) -> dict:
    """Substring-search one canon edition; returns matching pages with snippets."""
    return _search_canon(query, edition=edition, volume=volume,
                         limit=limit, offset=offset)


@mcp.tool()
def get_passage(edition: str, volume: int, page: int) -> dict:
    """Full text of one canon page in the given edition."""
    return _get_passage(edition, volume, page)


@mcp.tool()
def resolve_reference(platform: str, code: int, volume: int, page: int) -> dict:
    """Resolve a personal item's (platform, code, volume, page) to canon text."""
    return _resolve_reference(platform, code, volume, page)


@mcp.tool()
def lookup_dictionary(term: str, dictionary: str = 'pali_thai',
                      match: str = 'exact', limit: int = 20) -> dict:
    """Look up a term in pali_thai / pali_english / thai; match exact|prefix|contains."""
    return _lookup_dictionary(term, dictionary=dictionary, match=match, limit=limit)


def main():
    mcp.run()


if __name__ == '__main__':
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd mcp_server && . .venv/bin/activate && pytest tests/test_server.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Run the whole MCP suite**

Run: `cd mcp_server && . .venv/bin/activate && pytest -v`
Expected: PASS (all suites).

- [ ] **Step 6: Commit**

```bash
git add mcp_server/etipitaka_mcp/server.py mcp_server/tests/test_server.py
git commit -m "feat(mcp): FastMCP server with personal + canon tools"
```

---

## Task 12: README + sample client config

**Files:**
- Create: `mcp_server/README.md`

- [ ] **Step 1: Write the README**

Create `mcp_server/README.md`:

````markdown
# E-Tipitaka MCP Server

Exposes a user's personal E-Tipitaka data (bookmarks, highlights, tags,
history, saved lexicon) and the Buddhist canon (search, passage read, Pali/Thai
dictionaries, and personal→canon cross-reference) to MCP-capable AI clients.

## Install

```bash
cd mcp_server
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

## Configuration (environment variables)

Personal data (choose ONE auth method):
- `ETIPITAKA_BASE_URL` — default `https://data.etipitaka.com`
- `ETIPITAKA_USERNAME` + `ETIPITAKA_PASSWORD` — your web login; exchanged once
  for a token, which is cached at `~/.config/etipitaka-mcp/token` (mode 0600).
  The password is never stored.
- or `ETIPITAKA_TOKEN` — a pre-existing DRF token.

Canon (optional; enables the canon tools):
- `ETIPITAKA_RESOURCES_DIR` — path to the E-Tipitaka resources folder
  (e.g. `/Users/sutee/Works/watnapahpong/E-Tipitaka-PC/resources`).
- `ETIPITAKA_DEFAULT_EDITION` — default edition for `search_canon`
  (e.g. `thaiwn`).

## Tools

Personal: `list_bookmarks`, `list_highlights`, `list_tags`, `list_history`,
`list_lexicon`, `get_summary`, `whoami`.
Canon: `list_editions`, `search_canon`, `get_passage`, `resolve_reference`,
`lookup_dictionary`.

## Claude Desktop / Claude Code config

Add to `claude_desktop_config.json` (or an `.mcp.json`):

```json
{
  "mcpServers": {
    "etipitaka": {
      "command": "/absolute/path/to/mcp_server/.venv/bin/etipitaka-mcp",
      "env": {
        "ETIPITAKA_USERNAME": "your-username",
        "ETIPITAKA_PASSWORD": "your-password",
        "ETIPITAKA_RESOURCES_DIR": "/Users/sutee/Works/watnapahpong/E-Tipitaka-PC/resources",
        "ETIPITAKA_DEFAULT_EDITION": "thaiwn"
      }
    }
  }
}
```
````

- [ ] **Step 2: Commit**

```bash
git add mcp_server/README.md
git commit -m "docs(mcp): install + client config README"
```

---

## Final verification

- [ ] **Django suite + coverage:** `docker compose exec web python -m pytest` → PASS, ≥90%.
- [ ] **Golden replay:** `pytest tests/golden -v --base-url http://localhost:1338` → PASS.
- [ ] **MCP suite:** `cd mcp_server && . .venv/bin/activate && pytest -v` → PASS.
- [ ] **Smoke test the server:** with env vars set, run
  `cd mcp_server && . .venv/bin/activate && python -c "import etipitaka_mcp.server"`
  → no error; the process is launchable as `etipitaka-mcp`.
