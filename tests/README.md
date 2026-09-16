# Top-level test scripts

Everything under `app/user_data/tests/` runs through pytest inside the `web`
container (see the repo root `CLAUDE.md`). The scripts directly under
`tests/` (this directory) are different: each is a standalone check run by
hand against a live stack, documented in its own docstring/header. This file
just collects the exact commands in one place. `tests/golden/README.md`
covers the cross-stack golden HTTP regression harness separately.

## `oauth_e2e.py` -- remote MCP OAuth flow

Needs the golden seed users and the `mcp_server` venv on the host:

    docker compose exec -T web python manage.py seed_golden
    mcp_server/.venv/bin/python tests/oauth_e2e.py http://localhost:1338

See the file's own docstring for the flow and the DCR rate-limit caveat.

## `passkey_e2e.py` -- passkey login, recovery and signup flow

Runs *inside* the `web` container, piped in over stdin so it can import
Django directly (the software WebAuthn authenticator, the ORM, `django.test.
Client` for the recovery step -- see its own docstring) and still talk real
HTTP to a running server:

    docker compose exec -T web python - http://web:8000 < tests/passkey_e2e.py

Swap the URL for `http://localhost:1338` to go through nginx and exercise
the Task 23 rate-limit zones too (the default `http://web:8000` bypasses
nginx entirely) -- but only from somewhere `localhost:1338` actually
reaches nginx's published port with Django/Postgres access alongside it
(e.g. the docker host, not another `docker compose exec -T web`, whose own
loopback has no nginx listening on it). Expect it to end with
`PASSKEY E2E OK`; every step before that prints its own `... : OK` marker
as it completes. Repeated runs inside the same minute or so may hit the
passkey throttle (429) -- space runs out, or read the assertion message,
which names the request and response.

## `passkey_js_test.mjs` -- unit tests for `app/assets/passkey.js`

The `web` container has no node at all -- this runs on the **host** instead.
No test framework or npm install needed: `node:test` and `node:assert` are
both built into Node 18+. Written and last run against Node v20.18.1
(`/Users/sutee/.nvm/versions/node/v20.18.1/bin/node`); any reasonably
current Node on your PATH should do:

    node --test tests/passkey_js_test.mjs

This also asserts `node --check` cleanliness for every `app/assets/passkey*.js`
file and `app/assets/account_security.js` (its own last test case) -- so a
plain syntax error in any of those five files fails this same run. To check
just that, standalone:

    node --check app/assets/passkey.js
    node --check app/assets/passkey_login.js
    node --check app/assets/passkey_signup.js
    node --check app/assets/passkey_recover.js
    node --check app/assets/account_security.js

See the test file's own header comment for how it reaches the private
functions inside `passkey.js`'s IIFE (a `vm`-context load of the real,
unmodified source with one extra test-hook line spliced in at load time --
the committed file itself is never changed).
