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

## Localization note

The site is localized (Thai default, English via the `django_language`
cookie). Some surfaces are no longer cross-stack equivalent with the old
English-only stack and are intentionally same-stack:

- `test_behavioral.py` HTML-content assertions check the Thai default copy.
- Golden snapshots whose body carries a localized error message — the
  `rest_login_bad` login error, and the DRF authentication / not-found error
  cases (`sync_data_list_anon`, `user_data_list_anon`, `download_sync_data_404`,
  `download_user_data_denied`, `user_data_action_get_deleted`).
- The `/api/content/*` snapshots (`content_bookmarks_alice`,
  `content_bookmarks_anon`, `content_summary_alice`) are same-stack — these
  routes did not exist on the old stack.
- The public `/api/canon/*` snapshots (`canon_editions`, `canon_search`,
  `canon_passage`, `canon_dictionary`, `canon_search_unknown_edition`) are
  same-stack — these routes did not exist on the old stack. They read the tiny
  deterministic canon fixtures (`thai.sqlite`, `p2t_dict.sqlite`) the golden
  seed writes to `CANON_RESOURCES_DIR` (defaults to `media/canon`).
- `sync_data_list_alice` was re-recorded (and is now same-stack): the golden
  seed adds a `bookmark.sqlite` SyncData row for alice to back the content-API
  snapshots, which the old stack's seed did not create.
- The OAuth / remote-MCP discovery snapshots (`oauth_as_metadata`,
  `mcp_resource_metadata`, `mcp_unauthenticated`) are same-stack — the
  authorization server and the `mcp` service did not exist on the old stack.
  They advertise the canonical production issuer (`OAUTH_ISSUER_URL`,
  default `https://data.etipitaka.com`) regardless of the host under test.

All other golden snapshots (JSON data, tokens, file downloads, status codes)
are not localized and remain valid cross-stack regression checks.
