# Personal Data MCP Server — Design

**Date:** 2026-09-13
**Status:** Approved

## Goal

Give AI agents access to two related bodies of E-Tipitaka data through a Model
Context Protocol (MCP) server:

1. **A user's personal study data** — bookmarks, highlights, tags, search
   history, and saved lexicon terms — served from the Django backend.
2. **The Buddhist canon itself** — full-text search, passage read, and Pali /
   Thai dictionary lookup — read locally from the E-Tipitaka canon databases.

Because the MCP holds both, it can also **cross-reference** them: resolve a
user's bookmark or highlight `(code, volume, page)` to the actual canon text.
An agent can then answer questions such as *"what have I bookmarked in volume
11?"*, *"summarize the canon text behind my highlights tagged ขันธ์"*, *"find
canon pages that mention อานาปานสติ"*, or *"what does the Pali word ภว mean?"*.

The work has three parts:

1. **Content REST API** — new read-only Django REST Framework endpoints that
   open a user's per-platform SQLite sync databases and return normalized JSON.
2. **MCP server** — a local (stdio) Python server that (a) authenticates with
   the user's web credentials and calls the Content REST API for personal data,
   and (b) reads the local canon databases directly for search, passage read,
   dictionary lookup, and cross-reference. It exposes everything as MCP tools to
   AI clients (Claude Desktop, Claude Code, etc.).
3. **Canon registry + reader** — a small local module in the MCP server that
   maps the user's integer `code` (per platform) to a canon edition and file,
   and reads canon / dictionary SQLite databases read-only.

## Scope

**Personal data (via Django):**

- **Read-only.** No upload, delete, or sharing mutation.
- **Own data only.** The agent sees only the authenticated user's data; no
  follower / shared-owner access.
- **All five content types:** bookmarks, highlights, tags, history,
  saved lexicon.

**Canon data (local in the MCP):**

- **Full-text search** over canon editions (`content LIKE` substring, scoped by
  edition).
- **Passage read** by edition + volume + page.
- **Dictionary lookup** over three dictionaries: Pali→Thai (`p2t_dict.sqlite`),
  Pali→English (`pali-english.sqlite`), Thai (`thaidict.sqlite`).
- **Cross-reference:** resolve a user's `(platform, code, volume, page)` to the
  canon passage.
- **Read-only** on every canon / dictionary file. These are reference data and
  are never modified.

### Out of scope (v1, YAGNI)

- Writes of any kind (upload / soft-delete / add-remove follower).
- Follower / shared-owner data (the existing `Sharing` relationship).
- Remote hosting or OAuth 2.1 — the MCP runs locally over stdio.
- Shipping canon databases to the server — they stay local (1.4 GB), read by
  the MCP.
- A persistent FTS index — v1 uses `LIKE` substring search. FTS5-trigram is the
  documented upgrade path if latency demands it (see below).
- Item-number (`items`) lookup and the canon `mapping` tables — v1 addresses
  passages by volume + page only.
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

## Background: the canon resources

The canon databases live locally (default
`/Users/sutee/Works/watnapahpong/E-Tipitaka-PC/resources`, configurable) —
14 canon editions plus 3 dictionaries (17 SQLite files, ~1.4 GB total). Their
layout comes from the E-Tipitaka-PC app's `constants.py`.

**Canon edition schema** is uniform — one row per page:

```sql
CREATE TABLE main (volume VARCHAR(2), page VARCHAR(4), items VARCHAR(100), content TEXT);
-- indexed on (volume) and (volume, page)
```

`volume` / `page` are **zero-padded strings** in the canon (`'01'`, `'0101'`),
whereas the user's personal data stores them as integers (`volume=10`,
`page=101`). The reader must pad on lookup: `f"{int(volume):02d}"`,
`f"{int(page):04d}"`, and fall back to an unpadded match if the padded query
returns nothing (edition-specific padding differences).

**Edition registry** (embedded as static data in the MCP, sourced from
`constants.py` — the PC app is *not* imported):

- `code → filename`, e.g. `thai → thai.sqlite`, `thaiwn → thaiwn.sqlite`,
  `pali → pali.sqlite`, `palimc → palimc.sqlite`, `romanct → romanct.sqlite`.
  Full set: `thai, pali, thaiwn, thaimm, thaimc, thaimc2, thaipb, thaibt,
  romanct, palimc, thaims, thaivn, palinew, thaict`.
- Each entry also carries a human display name (Thai/English) from the PC app's
  `LANGS` list.

**Integer-code mapping** (the crucial join key). The user's personal data uses
integer `code`s, and the mapping differs by platform:

```python
IOS_CODE_TABLE     = {1:'thai', 2:'pali', 3:'thaimm', 4:'thaimc', 5:'thaibt',
                      6:'thaiwn', 7:'thaipb', 8:'romanct', 9:'palimc',
                      10:'thaims', 11:'thaivn', 12:'thaimc2'}
ANDROID_CODE_TABLE = {0:'thai', 1:'pali', 2:'thaimm', 3:'thaimc', 4:'thaibt',
                      5:'thaiwn', 6:'thaipb', 7:'romanct', 8:'palimc', 9:'thaivn'}
```

A `(platform, code)` pair resolves to an edition key, then to a file.

**Dictionary schemas** (all indexed on the head column → fast lookups):

| `dictionary` value | File                  | Table     | Columns |
|--------------------|-----------------------|-----------|---------|
| `pali_thai`        | `p2t_dict.sqlite`     | `p2t`     | `headword, content, type, gender, vachana, viphat, category, read, note, roman, eng_content, source` (66,752 rows) |
| `pali_english`     | `pali-english.sqlite` | `english` | `head, translation` (32,574 rows) |
| `thai`             | `thaidict.sqlite`     | `thai`    | `head, translation` (37,705 rows) |

## Architecture & data flow

The MCP server draws on two sources — remote personal data and local canon —
and can join them:

```
                        ┌─ HTTPS (Token) ─▶ Django /api/content/*  ──▶ sqlite_reader
AI client ──stdio──▶ MCP │                  (TokenAuth, own-data)       (per-platform user .sqlite, read-only)
                    server│
                        └─ local read ────▶ canon_reader / canon_registry
                                            (canon + dictionary .sqlite in ETIPITAKA_RESOURCES_DIR, read-only)
```

- **Personal data** flows over HTTPS through the Django Content REST API. Every
  endpoint merges across the user's platforms and tags each row with its
  `platform`.
- **Canon data** is read directly from local files; no network, no server.
- **Cross-reference** happens in the MCP: it fetches a personal item (with its
  `platform`, `code`, `volume`, `page`), maps `code`→edition via the registry,
  and reads the passage with `canon_reader`.
- The two sources are independent: canon tools work with no credentials, and
  personal-data tools work with no `ETIPITAKA_RESOURCES_DIR`. Cross-reference
  needs both.

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
virtualenv. It shares no runtime with the Django app. It has two backends: an
`httpx` client for personal data over HTTPS, and the local canon reader
(Component 4).

**Stack:** Python, the official `mcp` SDK (FastMCP), `httpx` for HTTP. Transport
is **stdio** (runs inside the user's AI client).

**Personal-data tools** (1:1 over the endpoints; same filter params as typed args):

- `list_bookmarks(platform?, code?, volume?, page?, important?, query?, limit?, offset?)`
- `list_highlights(platform?, code?, volume?, page?, query?, limit?, offset?)`
- `list_tags(platform?, query?, limit?, offset?)`
- `list_history(platform?, starred?, query?, limit?, offset?)`
- `list_lexicon(platform?, query?, limit?, offset?)`
- `get_summary()`
- `whoami()` — returns `/rest-auth/user/` (pk, username, email) for orientation.

**Canon tools** (local; require `ETIPITAKA_RESOURCES_DIR`):

- `list_editions()` — available editions: key, display name, whether the file
  is present. Plus the three dictionary keys.
- `search_canon(query, edition?, volume?, limit?, offset?)` — `content LIKE`
  substring search within one edition (defaults to `ETIPITAKA_DEFAULT_EDITION`).
  Returns `{items: [{edition, volume, page, items, snippet}], count, ...}`;
  `snippet` is a window of ±N chars around the first match. Full text via
  `get_passage`.
- `get_passage(edition, volume, page)` — the full `content` of one canon page,
  with `items`. `edition` is an edition key (e.g. `thai`, `thaiwn`).
- `resolve_reference(platform, code, volume, page)` — maps the integer `code`
  (+ platform) to an edition, then returns that passage. This is the primitive
  behind cross-reference; the personal-data tools return `platform`/`code`, so
  an agent can pipe a bookmark or highlight straight into this.
- `lookup_dictionary(term, dictionary, match?, limit?)` — `dictionary` is one of
  `pali_thai` / `pali_english` / `thai`; `match` is `exact` (default) /
  `prefix` / `contains` on the head column. Returns entries (Pali→Thai includes
  the extra `p2t` fields).

### Configuration (environment variables)

Personal data:

- `ETIPITAKA_BASE_URL` — default `https://data.etipitaka.com`.
- **Either** `ETIPITAKA_USERNAME` + `ETIPITAKA_PASSWORD` **or** a pre-existing
  `ETIPITAKA_TOKEN`.

Canon:

- `ETIPITAKA_RESOURCES_DIR` — path to the canon resources folder. If unset or
  missing, the canon tools return a clear "resources not configured" error and
  the personal-data tools keep working.
- `ETIPITAKA_DEFAULT_EDITION` — default edition for `search_canon` when none is
  given (e.g. `thaiwn`, the Watnapahpong edition).

### Authentication (credential → token exchange)

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

## Component 4: Canon registry & reader (local)

Two small modules inside `mcp_server/`, both operating only on local files.

### `canon_registry.py`

Static data + resolution helpers, sourced from the PC app's `constants.py` but
**copied in** (the PC app is never imported):

- `EDITIONS: {key → {filename, display_name}}` for all 14 edition keys.
- `IOS_CODE_TABLE` / `ANDROID_CODE_TABLE` (integer `code` → edition key).
- `DICTIONARIES: {key → {filename, table, head_column, extra_columns}}` for the
  three dictionaries.
- `edition_for(platform, code) -> key` and `path_for(key) -> resolved file path`
  (joined against `ETIPITAKA_RESOURCES_DIR`), with clear errors for unknown
  code / platform / missing file.

A unit test asserts the embedded tables match the current `constants.py` when
that file is reachable, so drift is caught (skipped when it isn't present).

### `canon_reader.py`

The only module that opens canon / dictionary files. Mirrors `sqlite_reader`'s
safety posture:

- Opens every file **read-only** (`file:<path>?mode=ro&immutable=1`).
- `search(edition_key, query, *, volume=None, limit, offset) -> (rows, total)` —
  `SELECT ... WHERE content LIKE ?` (`%term%`), optionally `AND volume = ?`
  (uses the volume index). Builds the `snippet` in Python from the match offset.
  A missing edition file → clear error, not a crash.
- `get_page(edition_key, volume, page) -> row | None` — zero-pads
  `volume`/`page`, falls back to an unpadded match if the padded lookup is
  empty.
- `lookup(dictionary_key, term, *, match, limit) -> rows` — `=` /
  `LIKE 'term%'` / `LIKE '%term%'` on the head column (indexed), returns the
  mapped columns.
- Fixed table/column names per registry entry; every value is parameter-bound —
  no SQL string interpolation.

**Latency note:** a `LIKE '%term%'` scan of one edition (`thai.sqlite` ≈ 90 MB,
19,701 rows) is a full-column scan — expect up to a few seconds. v1 bounds this
by searching one edition at a time and capping results. If that proves too slow,
the upgrade path is a persistent **FTS5 trigram** index built once per edition
and cached beside the resources; the reader would prefer it when present. Out of
scope for v1.

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

**MCP server — personal data (own test suite, mocked `httpx`):**

- Token lifecycle: mint from credentials, cache, reuse cached, use
  `ETIPITAKA_TOKEN`, refresh once on `401`.
- Tool schemas and argument passthrough to query params.
- Error mapping (401 / 404 / timeout).

**MCP server — canon (own test suite, tiny fixture DBs):**

- `canon_registry`: `edition_for` for iOS and Android codes, unknown
  code/platform errors, `path_for` missing-file error, and (when reachable) the
  drift check against `constants.py`.
- `canon_reader` against small hand-built `main`-schema fixtures: substring
  match + snippet, `volume` filter, pagination, zero-pad and unpad fallback in
  `get_page`, missing-file/missing-table handling, read-only enforcement.
- `lookup_dictionary` against tiny `p2t` / `english` / `thai` fixtures: exact /
  prefix / contains, extra-column passthrough for `pali_thai`.
- `resolve_reference` end to end on fixtures: `(platform, code, volume, page)`
  → edition → passage.

No Django or golden-harness changes for the canon layer — it is entirely local
to the MCP.

## Deliverables & suggested order

1. `sqlite_reader` helper + unit tests.
2. Content endpoints + URL wiring + tests + golden snapshots.
3. MCP server foundation: auth/token cache, httpx client, personal-data tools,
   tests.
4. `canon_registry` + `canon_reader` + tests.
5. Canon MCP tools (`list_editions`, `search_canon`, `get_passage`,
   `resolve_reference`, `lookup_dictionary`) + tests.
6. Docs: `mcp_server/README.md` with install steps, the two config groups
   (personal + canon env vars), and a sample client config
   (`claude_desktop_config.json` / `.mcp.json`).

## Open choices (decided, recorded for the record)

- **MCP implemented in Python, co-located in `mcp_server/`** — fits the team's
  stack; a separate repo or a TypeScript implementation was rejected as
  unnecessary friction.
- **Five typed endpoints** rather than one generic `/api/content/<type>/` route
  — clearer per-type schemas and filters, at the cost of slightly more code.
- **Canon runs locally in the MCP**, not on the server — the resource files are
  1.4 GB and already local; shipping them to data.etipitaka.com was rejected.
- **`LIKE` substring search for v1**, FTS5-trigram deferred — no build step, and
  substring is the natural match model for unsegmented Thai text.
- **Code tables copied into `canon_registry`**, not imported from the PC app —
  avoids coupling the MCP to that codebase; a test guards against drift.
