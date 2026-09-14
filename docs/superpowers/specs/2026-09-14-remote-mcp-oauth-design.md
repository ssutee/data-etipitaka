# Remote MCP Server with OAuth 2.1 — Design

**Date:** 2026-09-14
**Status:** Approved (design); implementation pending
**Supersedes/extends:** [[2026-09-13-personal-data-mcp-server-design]] (the local stdio
MCP), which keeps working unchanged.

## Goal

Make the E-Tipitaka MCP server usable from **mobile AI agent apps** (iOS /
Android) and any other client that only supports **remote** MCP connectors.

Today the server is a local **stdio** process: the client spawns
`etipitaka-mcp` on the same machine. Phones cannot do that. This design adds a
**remote MCP endpoint over Streamable HTTP** at `https://data.etipitaka.com/mcp`,
protected by **standards-based OAuth 2.1** so that a client adds it by URL,
logs the user in through their existing E-Tipitaka account, and then calls the
same 12 tools.

Decisions locked with the user:
- **Open standards** — not tied to one app. OAuth 2.1 with PKCE, dynamic
  client registration (RFC 7591), authorization-server metadata (RFC 8414),
  protected-resource metadata (RFC 9728). Any compliant client works.
- **Full OAuth 2.1 now** (not a bearer-token stopgap) so strict clients such as
  the Claude mobile app work with personal data immediately.
- **Approach A:** Django is the Authorization Server via
  **django-oauth-toolkit (DOT)**; the remote MCP service is a pure
  **Resource Server**. No third-party identity provider.

## Background: what the pieces already do

- **Django backend** (`data.etipitaka.com`, Django 5.2 / DRF, Docker Compose,
  nginx in front of gunicorn). Personal data at `/api/content/*` requires DRF
  `TokenAuthentication` (or session). Canon at `/api/canon/*` is **public**.
  Users log in at `/login/` with their web account.
- **MCP server** (`mcp_server/`, FastMCP from the `mcp` SDK, currently
  **1.30.0**, pinned `>=1.2.0,<2`). A thin HTTP client: `ContentClient`
  (adds one DRF token from env or the `~/.config/etipitaka-mcp/token` cache)
  and `CanonClient` (no auth). Exposes 12 tools.
- **MCP SDK auth model (verified in the SDK docs):** an MCP server is an OAuth
  2.1 **resource server**. Given `AuthSettings(issuer_url, resource_server_url,
  required_scopes)` plus a `TokenVerifier`, the SDK: validates `Authorization:
  Bearer` on every request, answers unauthenticated requests with **401 +
  `WWW-Authenticate` (resource_metadata=…)**, and publishes **RFC 9728
  Protected Resource Metadata** at `/.well-known/oauth-protected-resource/...`
  naming the authorization server. The SDK never signs users in or issues
  tokens — that is the AS's job.
- **DOT capabilities (verified in the DOT docs):** authorization-code +
  **PKCE (S256)**, **DCR** (`DCR_ENABLED`, `DCR_REGISTRATION_PERMISSION_CLASSES`,
  `/o/register/`), token endpoint, and DRF integration
  (`oauth2_provider.contrib.rest_framework.OAuth2Authentication`).

## Architecture

Two OAuth roles on the **same domain**, split by nginx:

```
                   https://data.etipitaka.com
                   ┌──────────── nginx ────────────┐
   /o/*, /.well-known/oauth-authorization-server,  │
   /api/*, /login/, everything else                │
                        │                          │  /mcp
                        ▼                          │  /.well-known/oauth-protected-resource*
              ┌──────────────────┐                 ▼
              │  web (gunicorn)  │        ┌──────────────────────┐
              │  Django + DOT    │◀───────│  mcp (uvicorn)       │
              │  = Authorization │  http://web:8000 (internal)  │
              │    Server        │        │  FastMCP streamable- │
              │  + REST API      │        │  http = Resource     │
              └──────────────────┘        │    Server            │
                                          └──────────────────────┘
```

- **Authorization Server** = Django + DOT under `/o/`. Issuer is the site
  root, `https://data.etipitaka.com`, so RFC 8414 discovery is simply
  `https://data.etipitaka.com/.well-known/oauth-authorization-server`.
- **Resource Server** = new `mcp` container: FastMCP over Streamable HTTP at
  `/mcp`, verifying bearer tokens by asking Django.
- **REST API** `/api/content/*` additionally accepts the same OAuth bearer
  token, so the MCP service just **forwards the caller's token**. Canon stays
  public.
- The **local stdio server is unchanged** in behaviour: one binary supports
  both transports (see Component 3).

## Component 1: Django as Authorization Server (django-oauth-toolkit)

**What it does:** dynamic client registration, user login + consent,
authorization-code + PKCE, token issuance/refresh, and a token-verification
endpoint for the resource server.

**Files:** `app/etipitaka_auth/settings.py`, `app/etipitaka_auth/urls.py`,
`app/requirements.txt`, new `app/user_data/oauth_views.py`,
`app/user_data/oauth_permissions.py`, template
`app/templates/oauth2_provider/authorize.html`.

**Dependency:** `django-oauth-toolkit` — pin the current 3.x release that
documents the `DCR_ENABLED` setting (the plan's first task verifies the exact
version installs on Python 3.13 / Django 5.2 and exposes `/o/register/`).

**Settings (`OAUTH2_PROVIDER`):**
- `SCOPES = {"etipitaka:read": "Read your E-Tipitaka bookmarks, highlights,
  tags, history and saved lexicon"}`; `DEFAULT_SCOPES = ["etipitaka:read"]`.
- `PKCE_REQUIRED = True`.
- `DCR_ENABLED = True`,
  `DCR_REGISTRATION_PERMISSION_CLASSES = ("oauth2_provider.dcr.AllowAllDCRPermission",)`.
  Open registration is the norm for MCP: any client may register, but a token
  still requires a real user to log in and consent.
- `ACCESS_TOKEN_EXPIRE_SECONDS = 3600`;
  `REFRESH_TOKEN_EXPIRE_SECONDS = 30 * 24 * 3600`; `ROTATE_REFRESH_TOKEN = True`.
- `ALLOWED_REDIRECT_URI_SCHEMES = ["https", "http"]` as the baseline (`https`
  covers web-callback clients such as the Claude app; `http` covers loopback
  redirects in dev). DOT rejects a DCR redirect URI whose scheme is not in this
  list, so a client that needs a custom scheme (e.g. `someapp://callback`) is
  onboarded by appending that scheme here — a settings change, no code. DCR
  supplies the redirect URIs; we do not pre-register any client.
- Add `oauth2_provider` to `INSTALLED_APPS`; run its migrations (additive:
  Application, Grant, AccessToken, RefreshToken, IDToken).

**URLs:**
- `path("o/", include("oauth2_provider.urls", namespace="oauth2_provider"))` —
  gives `/o/authorize/`, `/o/token/`, `/o/revoke_token/`, `/o/introspect/`,
  `/o/register/`.
- `GET /.well-known/oauth-authorization-server` → `oauth_views.as_metadata`, a
  small JSON view (RFC 8414) built from the request host:

  ```json
  {
    "issuer": "https://data.etipitaka.com",
    "authorization_endpoint": "https://data.etipitaka.com/o/authorize/",
    "token_endpoint": "https://data.etipitaka.com/o/token/",
    "registration_endpoint": "https://data.etipitaka.com/o/register/",
    "revocation_endpoint": "https://data.etipitaka.com/o/revoke_token/",
    "scopes_supported": ["etipitaka:read"],
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "code_challenge_methods_supported": ["S256"],
    "token_endpoint_auth_methods_supported": ["none", "client_secret_post"]
  }
  ```
  We serve this ourselves rather than enabling DOT's OIDC discovery, which
  would require an RSA key and OIDC settings we do not need (YAGNI).
- `GET /api/oauth/verify/` → `oauth_views.verify` — the resource server's
  token check (Component 3 calls it). Authentication:
  `OAuth2Authentication` only; permission: `IsAuthenticated` (any valid,
  unexpired OAuth token). It does **not** enforce scope itself — it reports
  the token's scopes so the MCP SDK can enforce `required_scopes` and answer
  a scope-less token with **403 `insufficient_scope`** (see Error handling);
  `/api/content/*` enforces the scope independently. Returns
  `200 {"active": true, "username", "user_id", "scopes": [...],
  "expires_at": <epoch>, "client_id"}`; an invalid/expired token yields DRF's
  `401`. This is functionally the RFC 7662 introspection answer, obtained by
  simply forwarding the user's own token — no confidential "resource server"
  client or client-credentials mint is needed. (RFC 7662 `/o/introspect/`
  remains available from DOT but is not used.)

**Consent screen:** override `oauth2_provider/authorize.html` to show the
requesting client's name and the human scope description in the site's i18n
(Thai default, English via the existing `django_language` cookie), with
Allow / Deny. DOT's `AuthorizationView` is login-required and redirects to the
existing `/login/` (`LOGIN_URL`), so no new login UI.

**Depends on:** the existing `User` model and login flow; DOT.

## Component 2: REST API accepts OAuth bearer tokens

**What it does:** lets the same OAuth access token that authenticates the MCP
session authenticate `/api/content/*`, without breaking the existing DRF-token
(stdio/desktop) and session paths.

**Files:** `app/user_data/content_views.py`, new
`app/user_data/oauth_permissions.py`, tests.

**Change:**
- `authentication_classes = (OAuth2Authentication, TokenAuthentication,
  SessionAuthentication)` on every `/api/content/*` view (the
  `_content_endpoint` factory and `summary`).
- `permission_classes = (ScopedOrAuthenticated,)` — a small custom permission:
  - if `request.auth` is an OAuth access token (has a `scope` attribute) →
    allow only if it is valid for `etipitaka:read`;
  - otherwise (DRF `Token` or session) → behave exactly like `IsAuthenticated`.

  DOT's own `TokenHasScope` cannot be used directly because it asserts when
  the request was authenticated by something other than OAuth2, which would
  break today's DRF-token clients.
- `/api/canon/*` untouched (public). `/rest-auth/*` untouched.

**Depends on:** Component 1 (DOT installed).

## Component 3: Remote MCP resource server (streamable-http)

**What it does:** serves the same 12 tools over Streamable HTTP at `/mcp`,
requires a valid OAuth bearer token, and forwards **the caller's token** to the
REST API so every user sees only their own data. The stdio transport keeps
working exactly as today.

**Files:** `mcp_server/etipitaka_mcp/config.py`, `client.py`, `server.py`, new
`verifier.py`, `pyproject.toml`, new `mcp_server/Dockerfile`, tests.

**Configuration (environment):**
- `ETIPITAKA_TRANSPORT` — `stdio` (default) | `http`.
- `ETIPITAKA_BASE_URL` — base for REST calls. Local stdio: the public site.
  In the `mcp` container: the **internal** `http://web:8000`.
- `ETIPITAKA_ISSUER_URL` — public AS issuer, `https://data.etipitaka.com`
  (http mode only).
- `ETIPITAKA_RESOURCE_URL` — public MCP URL, `https://data.etipitaka.com/mcp`
  (http mode only).
- `ETIPITAKA_HTTP_HOST` / `ETIPITAKA_HTTP_PORT` — bind address for uvicorn
  (default `0.0.0.0` / `8001`).
- Existing `ETIPITAKA_USERNAME/PASSWORD/TOKEN` and `ETIPITAKA_DEFAULT_EDITION`
  keep their meaning; the credential vars are used **only** in stdio mode.

**Server wiring (`server.py`):**
- stdio mode: as today — `FastMCP("etipitaka")`, `mcp.run()`.
- http mode:
  ```python
  mcp = FastMCP(
      "etipitaka",
      auth=AuthSettings(
          issuer_url=cfg.issuer_url,
          resource_server_url=cfg.resource_url,
          required_scopes=["etipitaka:read"],
      ),
      token_verifier=DjangoTokenVerifier(cfg.base_url),
      host=cfg.http_host, port=cfg.http_port,
      streamable_http_path="/mcp",
  )
  mcp.run(transport="streamable-http")
  ```
  The SDK then: rejects unauthenticated requests with 401 +
  `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp"`,
  enforces `etipitaka:read`, and serves the RFC 9728 document
  (`resource`, `authorization_servers: ["https://data.etipitaka.com"]`,
  `scopes_supported`, `bearer_methods_supported: ["header"]`).
- A second console script `etipitaka-mcp-http` is **not** added; the single
  `etipitaka-mcp` entry point reads `ETIPITAKA_TRANSPORT`.

**Token verification (`verifier.py`):**
```python
class DjangoTokenVerifier:                       # implements mcp TokenVerifier
    async def verify_token(self, token: str) -> AccessToken | None:
        # GET {base_url}/api/oauth/verify/ with Authorization: Bearer <token>
        # 200 -> AccessToken(token=token, client_id=body["client_id"],
        #                    scopes=body["scopes"], expires_at=body["expires_at"])
        # 401/403 -> None ; network error -> None (SDK answers 401)
```
- Uses `httpx.AsyncClient` (the verifier is async).
- A tiny in-process cache: successful results are remembered for **60 s**
  keyed by SHA-256 of the token, bounded to a few hundred entries, so a burst
  of Streamable-HTTP requests does not re-verify on every call. Negative
  results are not cached.

**Per-request token (`client.py` / `server.py`):**
- `ContentClient._get(path, params, token)` takes the token explicitly.
- A `current_token()` resolver:
  - http mode → `mcp.server.auth.middleware.auth_context.get_access_token()`
    (set by the SDK's `AuthContextMiddleware` for the request being served)
    → `.token`;
  - stdio mode → `Authenticator.token()` (env or cache), unchanged.
- The 401→re-mint retry stays **stdio-only**; in http mode a 401 from the API
  is returned as an error (the MCP client must refresh its token).
- Canon tools call `CanonClient` with no token in both modes.
- Tool names, parameters and result shapes are **identical** in both modes.

**Packaging / container (`pyproject.toml`, `Dockerfile`):**
- Add `uvicorn` to dependencies (the SDK's streamable-http runner uses it).
- `mcp_server/Dockerfile`: `python:3.12-slim`, copy the package, `pip install
  .`, `CMD ["etipitaka-mcp"]` with `ETIPITAKA_TRANSPORT=http` from compose.

**Depends on:** Component 2 (verify endpoint + bearer-accepting API), the
`mcp` SDK auth module (present in 1.30.0), `httpx`.

## Component 4: Hosting — docker-compose + nginx

**Files:** `docker-compose.yml`, `nginx/` config (the existing nginx image
build), `deploy.sh` unchanged.

- New service `mcp`: `build: ./mcp_server`, `expose: 8001`,
  `env_file: ./.env` plus:
  `ETIPITAKA_TRANSPORT=http`, `ETIPITAKA_BASE_URL=http://web:8000`,
  `ETIPITAKA_ISSUER_URL=https://data.etipitaka.com`,
  `ETIPITAKA_RESOURCE_URL=https://data.etipitaka.com/mcp`,
  `depends_on: web`. No volumes (canon is remote via Django).
- nginx:
  - `location /mcp` → `proxy_pass http://mcp:8001;` with
    `proxy_http_version 1.1; proxy_set_header Connection "";
    proxy_buffering off; proxy_read_timeout 3600;` (Streamable HTTP holds
    long-lived responses / SSE streams).
  - `location /.well-known/oauth-protected-resource` (prefix) → `mcp`.
  - `location = /.well-known/oauth-authorization-server` → `web`.
  - everything else → `web` as today.
- The mobile client only ever sees the public https URLs; the `mcp` service
  reaches Django on the internal compose network. DOT migrations run in the
  existing `deploy.sh` `migrate` step.
- Dev: `docker compose up -d` builds the `mcp` service locally too; the
  gitignored `docker-compose.override.yml` needs no change.

**CORS:** native mobile clients do not need CORS. A browser-based MCP client
would need `django-cors-headers` on `/o/token/`, `/o/register/` and the
well-known documents — **out of scope** until such a client is targeted.

## Data flow: a mobile client's first connection

1. User adds remote MCP `https://data.etipitaka.com/mcp` in the app.
2. App `POST /mcp` without a token → **401**, `WWW-Authenticate` points at
   `/.well-known/oauth-protected-resource/mcp` → `authorization_servers:
   ["https://data.etipitaka.com"]`, `scopes_supported: ["etipitaka:read"]`.
3. App fetches `https://data.etipitaka.com/.well-known/oauth-authorization-server`
   → endpoints incl. `registration_endpoint`.
4. App **registers itself** at `/o/register/` (DCR) → `client_id` (public
   client, PKCE).
5. App opens `/o/authorize/?response_type=code&client_id=…&code_challenge=…
   &code_challenge_method=S256&scope=etipitaka:read&redirect_uri=…` in a
   browser → Django redirects to `/login/` → user signs in with their
   E-Tipitaka account → **consent screen** → Allow → redirect with `code`.
6. App `POST /o/token/` (code + `code_verifier`) → access token (1 h) +
   refresh token (30 d, rotating).
7. App calls `/mcp` with `Authorization: Bearer <access>` → `initialize`,
   `tools/list`.
8. `DjangoTokenVerifier` → `GET /api/oauth/verify/` with that bearer → 200 →
   session allowed; result cached 60 s.
9. `list_bookmarks` → MCP forwards the **same** bearer to
   `/api/content/bookmarks/` → `OAuth2Authentication` resolves the user →
   `ScopedOrAuthenticated` checks `etipitaka:read` → the user's data.
10. `search_canon` → `/api/canon/search/` with no token (public).
11. Token expiry → API/verify returns 401 → MCP answers 401 → app uses the
    refresh token at `/o/token/` and retries.

## Security

- **HTTPS only** for every public endpoint (existing nginx TLS). Tokens are
  never logged (the verifier logs only a truncated SHA-256 on failure).
- **PKCE mandatory**, public clients, no client secrets on phones.
- **Scope enforcement at both layers:** the MCP SDK requires
  `etipitaka:read` on the session, and Django re-checks it on every
  `/api/content/*` call. Personal data remains **read-only** (only GET
  endpoints exist).
- **Own-data-only** is preserved automatically: the token identifies exactly
  one user, and the API filters by `request.user` as today.
- **Consent** is per user per client; refresh tokens rotate; revocation via
  `/o/revoke_token/`.
- **Audience binding:** the SDK advertises the resource (`/mcp`) in RFC 9728
  metadata and clients send `resource=` per the MCP spec; DOT's support for
  binding issued tokens to that resource is limited, so v1 relies on scope +
  issuer checks. Recorded as a **hardening follow-up** (see Out of scope).
- **Open DCR** cannot mint tokens by itself; abuse of `/o/register/` is bounded
  by nginx/DRF throttling (the existing login throttle applies to `/login/`).
- The `mcp` service is not reachable except through nginx; it talks to Django
  over the internal compose network.
- Existing DRF-token and session clients are **unaffected** (Component 2's
  permission falls back to `IsAuthenticated`).

## Error handling

| Situation | Behaviour |
|---|---|
| No / malformed / expired token on `/mcp` | SDK → **401** + `WWW-Authenticate` with `resource_metadata` |
| Token valid but lacks `etipitaka:read` | SDK → **403** (`insufficient_scope`) |
| `/api/oauth/verify/` unreachable (Django down) | verifier returns `None` → **401**; no internal detail leaked; logged server-side |
| API returns 401/403 for a forwarded token (revoked mid-session) | tool raises an error with the HTTP status; client refreshes / re-auths |
| Canon edition not provisioned | existing **503** from `/api/canon/*` surfaced as a tool error |
| DCR with unsupported redirect scheme | DOT → **400** `invalid_redirect_uri` |
| User denies consent | redirect with `error=access_denied` (DOT) |

## Testing

**Django (`app/user_data/tests/test_oauth.py`, pytest-django):**
- `/.well-known/oauth-authorization-server` returns the exact metadata (issuer
  = request host, all endpoints, `S256`, `etipitaka:read`).
- DCR: `POST /o/register/` creates an `Application` and returns `client_id`.
- Authorization-code + PKCE end to end with the test client: log in, GET
  `/o/authorize/` renders consent, POST allow → code, `POST /o/token/` → access
  + refresh tokens.
- `/api/oauth/verify/`: 200 + body (incl. `scopes`) for a valid token; 401
  for a bogus or expired token; a token **without** `etipitaka:read` still
  gets 200 with its actual scopes (scope enforcement is the SDK's and the
  content API's job, tested separately).
- `/api/content/bookmarks/`: 200 with an OAuth bearer; 403 with an OAuth token
  lacking the scope; **still 200 with a DRF token** and still 401 anonymous.
- `/api/canon/*` still public.
- Coverage stays ≥ 90 % (the existing gate).

**MCP (`mcp_server/tests/test_http_auth.py`, pytest + pytest-httpx):**
- `DjangoTokenVerifier`: 200 → `AccessToken` with scopes/expiry; 401/403/network
  error → `None`; second call within 60 s does not re-request.
- http-mode client: `current_token()` returns the request's bearer and
  `ContentClient` forwards it as `Authorization: Bearer`; no re-mint on 401.
- stdio-mode regression: existing tests unchanged and passing.
- ASGI-level test (Starlette test client): unauthenticated `POST /mcp` → 401
  with `WWW-Authenticate`; `GET /.well-known/oauth-protected-resource/mcp` →
  RFC 9728 body naming the issuer.

**Golden harness:** add `oauth_as_metadata`
(`GET /.well-known/oauth-authorization-server`) and `mcp_resource_metadata`
(`GET /.well-known/oauth-protected-resource/mcp`) as same-stack cases; both are
deterministic JSON. The CI golden job already builds the whole compose stack,
so the `mcp` service is exercised there.

**Integration script (`tests/oauth_e2e.py`, run by hand / in the plan):**
DCR → programmatic login + consent → token → `initialize` + one tool call on
`/mcp` against the local stack.

**Acceptance:** connect from a real mobile client, complete login + consent,
run `whoami` and `list_bookmarks`.

## Out of scope (v1)

- OpenID Connect / ID tokens; write scopes; more than one scope.
- Browser-based MCP clients (CORS) — add `django-cors-headers` when needed.
- Resource/audience-bound tokens beyond scope + issuer checks (hardening).
- Rate limiting on `/mcp` and `/o/register/` beyond existing throttles.
- Replacing the local stdio transport — it stays as the desktop path.
- Migrating existing DRF tokens to OAuth — both keep working side by side.

## Risks / notes

- **PyPI flakiness** seen this session may slow `pip install` of DOT/uvicorn
  in the container builds; CI has reliable network.
- DOT's DCR is recent — the plan's first task pins the version and checks
  `/o/register/` actually responds before building on it.
- Streamable HTTP through nginx needs buffering off and long timeouts; a
  misconfiguration shows up as hanging `tools/call` responses — covered by the
  integration script.
