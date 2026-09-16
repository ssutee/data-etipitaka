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
- The passkey snapshots (`apple_app_site_association`, `assetlinks_unset`,
  `passkey_login_begin`, `passkey_login_finish_bad_challenge`,
  `passkeys_list_anon`, `passkeys_list_alice`) are same-stack — these routes
  did not exist on the old stack. Random WebAuthn challenge values are masked
  as `<CHALLENGE>`. Record and assert **without** a `PASSKEY_RP_ID` /
  `PASSKEY_WEB_ORIGIN` dev override so `rpId` is the production default
  (`data.etipitaka.com`). `apple_app_site_association` is 200 in dev because
  `PASSKEY_IOS_APP_IDS` has a non-empty default
  (`A6DJDJ7527.com.watnapp.E-Tipitaka-Plus`); it would be a JSON 404 only if
  that setting were emptied. `assetlinks_unset` is a JSON 404 because
  `PASSKEY_ANDROID_PACKAGE` / `PASSKEY_ANDROID_CERT_SHA256` are unset by
  default — both 404 bodies are the hardcoded literal `"Not found."`, not run
  through `gettext`, so they stay English regardless of locale.
  `passkey_login_finish_bad_challenge` (400) and `passkeys_list_anon` (401)
  carry localized error messages — the harness sends no `Accept-Language`, so
  they come out in the site's default language, currently Thai; a locale
  change (e.g. changing `LANGUAGE_CODE`) will flip these two snapshots.

All other golden snapshots (JSON data, tokens, file downloads, status codes)
are not localized and remain valid cross-stack regression checks.
