# Personal Data MCP Server — Design

**Date:** 2026-09-13
**Status:** Approved

## Goal

Expose a user's personal E-Tipitaka study data — bookmarks, highlights, tags,
search history, and saved lexicon terms — to AI agents through a Model Context
Protocol (MCP) server. An agent can then answer questions over the user's own
data, for example *"what have I bookmarked in volume 11?"*, *"summarize my
highlights tagged ขันธ์"*, or *"which Pali terms have I saved?"*.

The work has two deliverables:

1. **Content REST API** — new read-only Django REST Framework endpoints that
   open a user's per-platform SQLite sync databases and return normalized JSON.
2. **MCP server** — a thin local (stdio) Python server that authenticates with
   the user's web credentials, calls those endpoints, and exposes them as MCP
   tools to AI clients (Claude Desktop, Claude Code, etc.).

## Scope

- **Read-only.** No upload, delete, or sharing mutation.
- **Own data only.** The agent sees only the authenticated user's data; no
  follower / shared-owner access.
- **All five content types:** bookmarks, highlights, tags, history,
  saved lexicon.

### Out of scope (v1, YAGNI)

- Writes of any kind (upload / soft-delete / add-remove follower).
- Follower / shared-owner data (the existing `Sharing` relationship).
- Remote hosting or OAuth 2.1 — the MCP runs locally over stdio.
- Canon body-text resolution — the server does not store scripture text (it
  lives in the client app bundle), so the agent works from the user's own
  references and text only.
- MCP resources and prompts — v1 is tools-only.

## Background: where the data lives

The five content databases are stored as `SyncData` rows whose `name` is the
SQLite filename, at `MEDIA_ROOT/<username>/<platform>/<name>`:

| `SyncData.name`      | Table      | Columns (observed)                                                                 |
|----------------------|------------|-------------------------------------------------------------------------------------|
| `bookmark.sqlite`    | `bookmark` | `created FLOAT, important INTEGER, note TEXT, rank INTEGER, code, volume, page`      |
| `highlight.sqlite`   | `highlight`| `selection TEXT, type INTEGER, note TEXT, start, end, volume, page, code, position` |
| `tag.sqlite`         | `tag`      | `name TEXT, history TEXT, note TEXT, highlight TEXT, priority INTEGER, code`         |
| `history.sqlite`     | `history`  | `keywords TEXT, created FLOAT, detail TEXT, code, starred, state, items, note, ...`  |
| `saved_lexicon.sqlite`| `lexicon` | `type INTEGER, head TEXT, translation TEXT`                                          |

Notes grounded in real data:

- `(code, volume, page)` locate an entry in the canon. `code` identifies the
  edition / scripture set.
- Timestamp floats (`bookmark.created`, `history.created`) are **Unix epoch**
  seconds (verified: `1457843335.09 → 2016-03-13`), not the Apple 2001 epoch.
- `highlight.selection` and `*.note` carry real Thai text — the substantive
  content an agent reasons over.
- A user may hold the same database on multiple platforms (`ios` / `pc` /
  `android`). Each is a separate `SyncData` row and a separate file.
- Column sets drift across app versions, so readers must not assume a fixed
  column list.

## Architecture & data flow

```
AI client ──stdio──▶ MCP server ──HTTPS (Token)──▶ Django /api/content/* ──▶ sqlite_reader
                     (mint/cache token)             (TokenAuth, own-data)     (per-platform .sqlite, read-only)
```

Every endpoint merges across the user's platforms and tags each returned row
with its `platform`.

## Component 1: `sqlite_reader` helper

**File:** `app/user_data/sqlite_reader.py`

The single isolated, unit-tested unit that touches SQLite. Nothing else opens a
database file directly.

**Interface:**

```python
def read_table(
    user,                 # Django User — owns the SyncData rows
    db_filename,          # e.g. "bookmark.sqlite"
    table,                # e.g. "bookmark"
    *,
    filters=None,         # {column: value} equality filters (parameterized)
    search=None,          # (columns, term) LIKE search across given columns
    platform=None,        # restrict to one platform; None = all
    limit=50,
    offset=0,
) -> tuple[list[dict], int]:   # (rows, total_count_before_limit)
    ...
```

**Behavior & guarantees:**

- Resolves matching `SyncData` files via `user.syncdata_set.filter(name=db_filename)`
  (optionally narrowed by `platform`).
- Opens each file **read-only** using a SQLite URI (`file:<path>?mode=ro&immutable=1`).
  A query path can never mutate the user's database.
- Reflects columns from `cursor.description` and returns a list of dicts —
  resilient to schema drift.
- Tags each row with its `platform`.
- Normalizes known timestamp columns (`created`) from Unix-epoch float to
  ISO-8601 strings; leaves an extra raw value out (normalized field only).
- The table name is fixed by the caller (one per content type); `WHERE`
  clauses use parameter binding only — no SQL string interpolation.
- Guards, each returning gracefully rather than raising:
  - file missing on disk → skip that platform,
  - table missing (checked via `sqlite_master`) → skip,
  - corrupt / unreadable database → skip that platform and log a warning.
- `total` is the count matching filters before `limit`/`offset`, aggregated
  across platforms, so callers can paginate.

## Component 2: Content REST endpoints

**File:** `app/user_data/content_views.py`, mounted under `/api/content/`
(added to `etipitaka_auth/urls.py`).

All endpoints: `GET` only, `TokenAuthentication` + `SessionAuthentication`,
`IsAuthenticated`, operate on `request.user` (own data only).

| Endpoint                    | Query params                                                    |
|-----------------------------|-----------------------------------------------------------------|
| `/api/content/bookmarks/`   | `platform, code, volume, page, important, q` (note), `limit, offset` |
| `/api/content/highlights/`  | `platform, code, volume, page, q` (selection+note), `limit, offset`  |
| `/api/content/tags/`        | `platform, q` (name), `limit, offset`                           |
| `/api/content/history/`     | `platform, starred, q` (keywords), `limit, offset`              |
| `/api/content/lexicon/`     | `platform, q` (head), `limit, offset`                           |
| `/api/content/summary/`     | none                                                            |

**List response shape:**

```json
{
  "items": [ { "...row fields...": "...", "platform": "ios" } ],
  "count": 42,
  "limit": 50,
  "offset": 0
}
```

**`summary` response:** per-type, per-platform row counts plus the username, so
an agent can orient before drilling in:

```json
{
  "username": "Laksana",
  "platforms": ["ios"],
  "counts": {
    "bookmarks":  {"ios": 2},
    "highlights": {"ios": 35},
    "tags":       {"ios": 20},
    "history":    {"ios": 0},
    "lexicon":    {"ios": 0}
  }
}
```

**Pagination bounds:** default `limit` 50, maximum 500 (clamped), to keep agent
context bounded. Invalid `limit`/`offset` fall back to defaults.

Each endpoint is a thin wrapper: parse and validate params → call
`sqlite_reader.read_table` with the fixed table and the allowed filters → return
`JsonResponse`.

## Component 3: MCP server

**Location:** `mcp_server/` at the repo root, with its own `pyproject.toml` and
virtualenv. It shares no runtime with the Django app — it is a standalone HTTP
client.

**Stack:** Python, the official `mcp` SDK (FastMCP), `httpx` for HTTP. Transport
is **stdio** (runs inside the user's AI client).

**Tools** (1:1 over the endpoints; same filter params surfaced as typed args):

- `list_bookmarks(platform?, code?, volume?, page?, important?, query?, limit?, offset?)`
- `list_highlights(platform?, code?, volume?, page?, query?, limit?, offset?)`
- `list_tags(platform?, query?, limit?, offset?)`
- `list_history(platform?, starred?, query?, limit?, offset?)`
- `list_lexicon(platform?, query?, limit?, offset?)`
- `get_summary()`
- `whoami()` — returns `/rest-auth/user/` (pk, username, email) for orientation.

### Authentication (credential → token exchange)

Configuration via environment variables:

- `ETIPITAKA_BASE_URL` — default `https://data.etipitaka.com`.
- **Either** `ETIPITAKA_USERNAME` + `ETIPITAKA_PASSWORD` **or** a pre-existing
  `ETIPITAKA_TOKEN`.

Token lifecycle:

1. If a cached token exists and `GET /rest-auth/user/` accepts it, use it.
2. Otherwise, if `ETIPITAKA_TOKEN` is set, use and cache it.
3. Otherwise `POST /rest-auth/login/` with `{username, password}`; the response
   `{"key": ...}` is cached.
4. The token is cached at `~/.config/etipitaka-mcp/token` (file mode `0600`),
   or the OS keyring when the `keyring` package is available.
5. Every content request sends `Authorization: Token <key>`.
6. A `401` triggers exactly one re-mint (re-run steps 2–3), then a clear
   `authentication failed` error to the agent.

The raw password is never persisted and never sent after the first exchange.
`/rest-auth/logout/` (invoked manually by the user, or a future `logout` tool)
revokes the token.

### Error handling

Single `httpx` client with a timeout. Map failures to clear, agent-facing
messages: `401` → authentication failed; `403`/`404` → not found / not
permitted; timeout / network error → transient error with the base URL named.
Tool payloads stay bounded by the endpoint `limit`.

## Testing

**Django (pytest, existing 90% coverage gate; project currently at 100%):**

- `sqlite_reader` unit tests with temporary `SyncData` rows backed by temporary
  `.sqlite` fixtures: empty DB, populated DB, missing table, corrupt file,
  multi-platform merge, timestamp normalization, filter + search + pagination,
  own-data isolation.
- Endpoint tests for each route: authentication required (401 without token),
  own-data isolation (user A cannot read user B), each filter, pagination
  clamping, `summary` counts.
- **Golden harness:** add HTTP regression snapshots for the six read routes
  (see `tests/golden/README.md`).

**MCP server (own test suite, mocked `httpx`):**

- Token lifecycle: mint from credentials, cache, reuse cached, use
  `ETIPITAKA_TOKEN`, refresh once on `401`.
- Tool schemas and argument passthrough to query params.
- Error mapping (401 / 404 / timeout).

## Deliverables & suggested order

1. `sqlite_reader` helper + unit tests.
2. Content endpoints + URL wiring + tests + golden snapshots.
3. MCP server: auth/token cache, httpx client, tools, tests.
4. Docs: `mcp_server/README.md` with install steps and a sample client config
   (`claude_desktop_config.json` / `.mcp.json`).

## Open choices (decided, recorded for the record)

- **MCP implemented in Python, co-located in `mcp_server/`** — fits the team's
  stack; a separate repo or a TypeScript implementation was rejected as
  unnecessary friction.
- **Five typed endpoints** rather than one generic `/api/content/<type>/` route
  — clearer per-type schemas and filters, at the cost of slightly more code.
