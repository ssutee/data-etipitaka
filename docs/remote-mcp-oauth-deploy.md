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
Django's `SECURE_PROXY_SSL_HEADER`. The parser accepts `1`, `true`, `yes`
case-insensitively (see `TRUST_PROXY_PROTO` in
`app/etipitaka_auth/settings.py`). `TRUST_PROXY_PROTO` is intentionally not
read from `.env`, since `.env` is tracked and shared with production.

Until it's enabled, dynamic client registration hands back an `http://`
`registration_client_uri` regardless of the actual scheme — see above.

## Rate limiting and throttled responses

`nginx/nginx.conf` rate-limits `/mcp` and dynamic client registration
(`/o/register/` and `/o/register`, both spellings — the per-client
management URLs nested beneath registration, e.g. `/o/register/<id>/`, are
not limited). A throttled request gets `429` with a `Retry-After` header and
a small JSON body (`{"error":"rate_limited",...}`) instead of nginx's stock
HTML error page, so a JSON-RPC client mid-session gets something it can
parse and act on.

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
