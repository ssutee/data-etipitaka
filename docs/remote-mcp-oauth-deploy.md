# Deploying the remote MCP endpoint and OAuth 2.1 authorization server

This stack runs an OAuth 2.1 authorization server (django-oauth-toolkit, open
dynamic client registration) plus a remote MCP endpoint at `/mcp`, fronted by
the `nginx` container in this repo (`nginx/nginx.conf`). **In production a
separate host-level nginx terminates TLS in front of this container** — that
host config lives on the server, not in this repo. This document is the
contract that host proxy must satisfy, and what silently breaks if it
doesn't.

## The host-proxy contract

The host-level TLS terminator that sits in front of the `nginx` container
must set **two** headers on every request it forwards, and must overwrite
rather than pass through either one if a client already sent it:

- **`X-Forwarded-Proto`** — `proxy_set_header X-Forwarded-Proto $scheme;`
  on its forwarded location(s).
- **`X-Forwarded-For`** — the client's real address, not merely appended-to
  if already present from an untrusted hop.

Both must be **overwritten**, not passed through, because this container's
`nginx.conf` trusts them unconditionally from any peer in the private
ranges it lists (`set_real_ip_from` / the container network) — including the
host proxy itself. If the host proxy forwards a client-supplied value
instead of setting its own, a client can spoof either header.

### What breaks if `X-Forwarded-Proto` is missing or not overwritten

Django's `SECURE_PROXY_SSL_HEADER` (enabled via `TRUST_PROXY_PROTO`, below)
trusts this header to decide `request.is_secure()`. If the host proxy
doesn't set it, dynamic client registration keeps handing clients an
`http://` `registration_client_uri` management URL alongside a bearer
`registration_access_token`, even though the request arrived over TLS. If
the host proxy passes through a client-supplied value instead of
overwriting it, a client can spoof "secure" on a plaintext request.

### What breaks if `X-Forwarded-For` is missing

`nginx/nginx.conf` uses `real_ip_header X-Forwarded-For` to recover the true
client address; that recovered address is what the per-client rate-limit
buckets (`limit_req_zone $binary_remote_addr ...`) key on. If the host proxy
does not send this header, every request nginx sees has `remote_addr` equal
to the host proxy's own (trusted, private) address, so **every client in the
world shares a single rate-limit bucket**. Measured shape: 40 requests from
one address gave 19 rejections, while 40 requests from distinct addresses
gave none. In production this becomes a global ceiling — legitimate
concurrent sessions throttle each other and it reads as an outage, not as
rate limiting working correctly.

## Enabling `TRUST_PROXY_PROTO`

Once `X-Forwarded-Proto` is confirmed set-and-overwritten by the host proxy
(above), enable the opt-in for the `web` service:

```
TRUST_PROXY_PROTO=1
```

via `docker-compose.override.yml` (gitignored, prod-side override file — the
same mechanism used for `CANON_RESOURCES_DIR` in
[`docs/canon-remote-deploy.md`](canon-remote-deploy.md)). This turns on
**three** things together (see `TRUST_PROXY_PROTO` in
`app/etipitaka_auth/settings.py`): Django's `SECURE_PROXY_SSL_HEADER`, and
`SESSION_COOKIE_SECURE` / `CSRF_COOKIE_SECURE` — the session and CSRF
cookies become HTTPS-only. The parser accepts `1`, `true`, `yes`
case-insensitively. `TRUST_PROXY_PROTO` is intentionally not read from
`.env`, since `.env` is tracked and shared with production.

Until it's enabled, dynamic client registration hands back an `http://`
`registration_client_uri` regardless of the actual scheme, and
password-reset emails link to `http://` instead of `https://`
(`PasswordResetView.form_valid` passes `use_https=request.is_secure()`,
which without this flag is always `False`) — see above.

**Once it's enabled, plain HTTP access to the published `1338:80` port
stops working for anything that needs a cookie.** A browser will not send
a `Secure` cookie back over plain HTTP, so hitting the container directly
at `http://<host>:1338` — bypassing the TLS-terminating host proxy this
flag assumes is always in front — silently breaks login, CSRF, and any
session-backed page for that visitor: the request still succeeds at the
HTTP level, the cookie is simply never sent back. Only turn this on once
the host proxy is confirmed to be the sole public path to port 1338 (see
"Recommended follow-up" below).

## Rate limiting and throttled responses

`nginx/nginx.conf` rate-limits two families of paths: the original OAuth/MCP
surface, and the passkey/account-recovery surface added since.

OAuth / MCP:

- `/mcp` — 10 req/s, burst 20.
- `/o/register/` (dynamic client registration, both spellings — the
  per-client management URLs nested beneath it, e.g. `/o/register/<id>/`,
  are not limited) — 6 req/min, burst 5.
- `/o/token/` (authorization-code exchange and refresh) — 30 req/min,
  burst 5. A legitimate client hits this once per authorization and once
  per refresh; anything faster is a client minting tokens in a loop.
- `/api/oauth/verify/` — 10 req/s, burst 20, mirroring the `/mcp` limit.
  The MCP container calls this endpoint on every tool call, but over the
  internal docker network (`http://web:8000`), bypassing this proxy
  entirely — so this limit exists only to stop the `/mcp` rate limit from
  being routed around by hitting the resource-server check directly.

Passkeys and account recovery (anonymous, or reached before any session
exists, so the client IP is the only key available):

- `/login/passkey/` (both spellings), `/account/recover/passkey/*`, and
  `/api/passkeys/(login|signup)/*` — 60 req/min, burst 30. Loose enough to
  absorb carrier-grade NAT / a large office sharing one public IP, and the
  login page's own conditional-mediation autofill (a `login/begin` on
  every page view, plus a refresh every 270s for every open tab).
  Credential guessing itself is stopped by single-use challenges, required
  user verification and a DRF-level throttle, not by this zone.
- The rest of `/api/passkeys/*` — signed-in management: list/rename/delete
  an existing passkey, register a new one, remove the password fallback —
  60 req/min, burst 20.
- `/password_reset/` and the `/reset/<uidb64>/...` confirm flow — split by
  HTTP method, because a normal recovery is already a GET (the email
  link) → GET (the `.../set-password/` redirect Django sends a valid
  token to) → POST sequence, and a single shared budget left almost
  nothing for a second attempt. GETs get 20 req/min, burst 10; POSTs — the
  two actions that actually do something, mailing an address and setting
  a password — get 5 req/min, burst 3.

Every passkey/recovery location above also caps the request body at 64 KiB
(`client_max_body_size 64k`; the server-wide default, set at the top of the
file, is unlimited). `/.well-known/*` matches none of these locations and
is never rate-limited — confirmed with a 30-request burst against each
`.well-known` path returning zero `429`s — because a `429` to Apple's or
Google's crawler there risks the domain being marked unreachable.

A throttled request gets `429` with a `Retry-After` header. Every location
above except the password-reset/reset-confirm one returns a small JSON
body instead of nginx's stock HTML error page, so a JSON-RPC or `fetch()`
caller mid-session gets something it can parse and act on; the passkey
bodies also carry a `"detail"` key (`{"error":"rate_limited",
"retry_after":1,"detail":"..."}` — additive, so a client that only reads
`error`/`retry_after` still works). `/password_reset/` and the
reset-confirm flow are the one exception: that surface is reached by a
browser following an emailed link, not a script, so its `429` renders a
small HTML page instead of a JSON blob a person would otherwise see raw.

## Token table growth — schedule `cleartokens`

Dynamic client registration is open and refresh tokens are long-lived (30
days), so `oauth2_provider`'s access/refresh/grant tables grow without
bound under normal use, not just abuse. Schedule
`docker compose exec -T web python manage.py cleartokens` to run
periodically (e.g. daily via cron/systemd timer on the host) to prune
expired tokens and grants. There is no cron process inside this compose
stack today — the operator must add one.

## Recommended follow-up (not applied here — operator to confirm and apply)

- **Bind the published port to loopback.** `docker-compose.yml` currently
  publishes the container's port on all interfaces (`1338:80`). Binding it
  to loopback instead (`127.0.0.1:1338:80`) would make the breadth of the
  trusted-proxy ranges in `nginx.conf`
  (`set_real_ip_from`) moot, because only the host proxy could reach the
  container at all. This is **not** changed by this document or the commits
  that accompany it — verifying what address the production host proxy
  uses to reach the container is required first, and getting it wrong takes
  the site down. Confirm on the host, then apply.

## Restarting after config or code changes

- **nginx:** `nginx.conf` is baked into the image at build time, so
  `docker compose up -d --build nginx` is required — a plain `restart` does
  not pick up config changes.
- **web (Django):** gunicorn does not reload on code changes; the container
  needs to be recreated or restarted. The deploy script already does this
  via `up -d --build`, so this matters only for manual intervention outside
  that script.
