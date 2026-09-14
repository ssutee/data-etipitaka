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
`app/user_data/oauth_authentication.py`, `app/user_data/oauth_permissions.py`,
template
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
  `REFRESH_TOKEN_EXPIRE_SECONDS = 30 * 24 * 3600`; `ROTATE_REFRESH_TOKEN = True`;
  `REFRESH_TOKEN_REUSE_PROTECTION = True`.
- `OIDC_ISS_ENDPOINT = OAUTH_ISSUER_URL` (DOT's issuer knob, derived from the
  same setting the metadata view uses — one source of truth) and the RFC 9700
  gates `COMPLIANT_BCP_RFC9700_PKCE_METHOD`, `_IMPLICIT_GRANT`,
  `_PASSWORD_GRANT`, `_ACCESS_TOKEN_TRANSPORT`, `_AUTHZ_RESPONSE_ISS` all
  `True`, so the server enforces exactly what the metadata advertises.
- `ALLOWED_REDIRECT_URI_SCHEMES = ["https", "http"]` as the baseline (`https`
  covers web-callback clients such as the Claude app; `http` covers loopback
  redirects in dev). DOT rejects a DCR redirect URI whose scheme is not in this
  list, so a client that needs a custom scheme (e.g. `someapp://callback`) is
  onboarded by appending that scheme here — a settings change, no code. DCR
  supplies the redirect URIs; we do not pre-register any client.
- Add `oauth2_provider` to `INSTALLED_APPS`; run its migrations (additive:
  Application, Grant, AccessToken, RefreshToken, IDToken).

**URLs:**
- `path("o/", include((oauth2_urls.base_urlpatterns + oauth2_urls.dcr_urlpatterns,
  "oauth2_provider"), namespace="oauth2_provider"))` — mounts **only** DOT's
  base routes (`/o/authorize/`, `/o/token/`, `/o/revoke_token/`,
  `/o/introspect/`) and DCR (`/o/register/`). DOT's application-management
  UI (`/o/applications/…`, which would let any signed-in user create arbitrary
  clients) and its own `/o/.well-known/*` documents are deliberately not
  mounted. Because `oauth2_provider:detail` is therefore unmounted, the admin
  re-registers `Application` with `view_on_site = False`.
- `GET /.well-known/oauth-authorization-server` → DOT's
  `OAuthServerMetadataView` mounted at the site root (RFC 8414). It anchors
  every URL on `OIDC_ISS_ENDPOINT` (never the request, so it advertises
  `https` behind nginx) and filters the advertised lists through the same
  RFC 9700 gates the server enforces. Example document:

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
    "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
    "revocation_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
    "introspection_endpoint": "https://data.etipitaka.com/o/introspect/",
    "authorization_response_iss_parameter_supported": true,
    "client_id_metadata_document_supported": false
  }
  ```
  DOT's plain OAuth metadata view needs no OIDC/RSA setup. The lists come
  from `OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED` (`none` for public DCR
  clients), `OAUTH2_RESPONSE_TYPES_SUPPORTED = ["code"]` and
  `OAUTH2_GRANT_TYPES_SUPPORTED = ["authorization_code", "refresh_token"]`.
  `OAUTH_ISSUER_URL` is normalised (`rstrip('/')`) once in settings, so the
  metadata `issuer` and the RFC 9207 `iss` value are always identical. Only
  DOT's `/o/.well-known/*` *location* is avoided (wrong issuer path), not its
  view. The view also sends `Access-Control-Allow-Origin: *`.
- `GET /api/oauth/verify/` → `oauth_views.verify` — the resource server's
  token check (Component 3 calls it). Authentication:
  `ActiveUserOAuth2Authentication` (in `oauth_authentication.py`, shared
  with Component 2) only — DOT's `OAuth2Authentication`
  subclassed to also reject tokens not bound to an active user: a user set
  inactive after consenting (DOT validates the token, not the account;
  without this a deactivated user could keep verifying and refreshing for the
  refresh-token lifetime) and user-less client-credentials tokens (DOT stores
  `user = None` for them; reachable through open DCR). Both are answered
  `401 invalid_token`. Permission: `IsAuthenticated`. It does **not** enforce
  scope itself — it reports
  the token's scopes so the MCP SDK can enforce `required_scopes` and answer
  a scope-less token with **403 `insufficient_scope`** (see Error handling);
  `/api/content/*` enforces the scope independently. Returns
  `200 {"active": true, "username", "user_id", "scopes": [...],
  "expires_at": <epoch seconds>, "client_id"}` with `Cache-Control: no-store`;
  `client_id` is always a string (`""` for a token without an application)
  because the MCP side builds `AccessToken(client_id=str)` from it. An
  invalid/expired token, a missing header, an inactive user, or a user-less
  (client-credentials) token yields `401` with a `WWW-Authenticate: Bearer`
  challenge. This is functionally the RFC 7662 introspection answer, obtained by
  simply forwarding the user's own token — no confidential "resource server"
  client or client-credentials mint is needed. (RFC 7662 `/o/introspect/`
  remains available from DOT but is not used.)

**Consent screen:** override `oauth2_provider/authorize.html` to show the
requesting client's name and the human scope description in the site's i18n
(Thai default, English via the existing `django_language` cookie), with
Allow / Deny. DOT's `AuthorizationView` is login-required and redirects to the
existing `/login/` (`LOGIN_URL`), so no new login UI. Details that matter:
- The template extends the site's `base.html`, which boots AngularJS on
  `<html>` with `<[ ]>` interpolation delimiters. Angular interpolates DOM
  text after entity decoding, so autoescaping alone does not stop a
  DCR-registered `client_name` such as `<[7*7]>` from being evaluated in the
  consenting user's session. The consent container is therefore
  `ng-non-bindable`, and a test registers such a client and asserts the name
  is shown verbatim.
- Deny is first in the DOM (Enter never grants); `form.errors` is rendered so
  a tampered hidden field explains itself.
- The six template strings and the scope description (`gettext_lazy` in
  `OAUTH2_PROVIDER['SCOPES']`) have entries in the Thai catalog
  (`app/locale/th/LC_MESSAGES/django.po`; `.mo` compiled by hand with
  `msgfmt` and committed, as for the rest of the site).

**Depends on:** the existing `User` model and login flow; DOT.

## Component 2: REST API accepts OAuth bearer tokens

**What it does:** lets the same OAuth access token that authenticates the MCP
session authenticate `/api/content/*`, without breaking the existing DRF-token
(stdio/desktop) and session paths.

**Files:** `app/user_data/content_views.py`, new
`app/user_data/oauth_permissions.py`, `app/user_data/oauth_authentication.py`
(the authenticator Component 1's verify endpoint uses), tests.

**Change:**
- `authentication_classes = (ActiveUserOAuth2Authentication,
  TokenAuthentication, SessionAuthentication)` on every `/api/content/*` view
  (the `_content_endpoint` factory and `summary`) — the same inactive-user-
  rejecting subclass the verify endpoint uses, so all three authenticators
  agree that a deactivated account is rejected.
- `permission_classes = (ScopedOrAuthenticated,)` — a small custom permission:
  - if `request.auth` is an OAuth access token (has a `scope` attribute) →
    allow only if it is valid for `etipitaka:read`; otherwise answer `403`
    with `WWW-Authenticate: Bearer realm="api",error="insufficient_scope",
    scope="etipitaka:read"` (RFC 6750 §3.1);
  - otherwise (DRF `Token` or session) → behave exactly like `IsAuthenticated`.

  DOT's `IsAuthenticatedOrTokenHasScope` would do the same job, but it reads
  `required_scopes` off the view class, which function-based `api_view`
  views do not carry; with one fixed scope a small explicit permission is
  clearer.
- `/api/canon/*` untouched (public).
- `GET /rest-auth/user/` gets the same stack, because the `whoami` tool calls
  it. This was missed until the end-to-end run: eleven of the twelve tools
  went through `/api/content/*` and worked remotely, while `whoami` returned
  401 for every remote caller. The rest of `/rest-auth/*` is untouched — in
  particular logout stays on the legacy stack, since a read-scoped OAuth
  token should not be able to delete the caller's DRF token.
- Consequence of listing the OAuth authenticator first: DRF builds the
  anonymous `401` challenge from the first authenticator, so `/api/content/*`
  answers `WWW-Authenticate: Bearer realm="api"` instead of `Token`.
  Authenticated responses are unchanged; existing DRF-token clients only send
  the header, they never parse the challenge. The golden snapshot
  `content_bookmarks_anon` is re-recorded to match.
- DOT's authenticator now runs on every `/api/content/*` request, DRF-token
  ones included. Two edge behaviours change, both only for broken clients: a
  query string with malformed percent-encoding (`?q=%zz`) is rejected by
  oauthlib as `400` where it used to be served, and an invalid `Token …`
  header is answered with the `Bearer` challenge (status and body
  unchanged).

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
- `ETIPITAKA_ALLOWED_HOSTS` — hosts the SDK's DNS-rebinding protection accepts
  (default `localhost:*,127.0.0.1:*,[::1]:*`). nginx forwards the original
  `Host`, so production adds its public hostname. An empty value means the
  operator deliberately emptied it, not "unset": the default lives in one
  module constant shared by both the dataclass and the environment reader.
- `ETIPITAKA_ALLOWED_ORIGINS` — origins the same protection accepts (default
  empty). With none configured the SDK rejects any request that *carries* an
  `Origin` header; requests without one pass. Native clients send no `Origin`,
  so the default suits them, and a browser-based client needs its site listed.
- `ETIPITAKA_TRANSPORT` is normalised and validated: anything outside
  `stdio`/`http` raises rather than silently falling back to stdio. The issuer
  and resource URLs have a trailing slash stripped, matching how Django
  normalises its own issuer.
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
      transport_security=TransportSecuritySettings(
          enable_dns_rebinding_protection=True,
          allowed_hosts=cfg.allowed_hosts,
          allowed_origins=cfg.allowed_origins),
  )
  mcp.run(transport="streamable-http")
  ```
  `validate_token_resource=False` is set explicitly: this deployment's clients
  never send a `resource` parameter and the verify endpoint returns none, so
  the verifier has nothing to propagate. If that changes, the verifier can set
  `AccessToken.resource` and the flag can be flipped. http mode exits with a
  clear message if either public URL is missing.

  The SDK then: rejects unauthenticated requests with 401 +
  `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp"`,
  enforces `etipitaka:read`, and serves the RFC 9728 document
  (`resource`, `authorization_servers: ["https://data.etipitaka.com/"]`,
  `scopes_supported`, `bearer_methods_supported: ["header"]`).

  That `authorization_servers` entry carries a trailing slash while the AS
  metadata reports `issuer` without one, because the SDK's URL type always
  renders a root issuer with the slash. This is expected and correct: the
  reference client compares the two as equal (RFC 3986 §6.2.3) while still
  rejecting genuine mismatches. Do not "fix" it by adding a slash to Django's
  issuer — that would produce double-slashed endpoint URLs.
- **The twelve tool functions are `async`** and hand their blocking REST call
  to `anyio.to_thread.run_sync`. FastMCP invokes a *synchronous* tool body
  inline on the request's own task, so a blocking call would serialise every
  other session on the worker — measured at 0.319 s for two concurrent 0.15 s
  calls before the change, 0.163 s after. anyio specifically is required
  because it copies the context into the worker thread, which is what keeps
  the per-request bearer token resolving there; a bare thread pool would not
  and would silently break per-caller isolation.
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
- The cache never extends a token's life: the SDK re-checks the absolute
  `expires_at` on every request. It delays only **revocation**, by at most the
  cache TTL. Cache hits hand out deep copies, so no caller can mutate the
  token another caller will receive.
- It fails closed on anything doubtful, because "no answer" must mean 401 and
  never a 500: a malformed body, an unexpected field type, an invalid base URL
  and a network error all return `None`. A 200 whose body is not `active` is
  rejected too. `subject` is populated from the verify response's `user_id`,
  which the SDK uses when binding a session to its owner.
- Anything other than a 401 is logged with the status and a truncated token
  digest. A 401 stays silent because it is routine; without this a wrong base
  URL would look exactly like every client presenting a bad token.

**Per-request token (`client.py` / `server.py`):**
- `ContentClient(base_url, token_provider, refresh=None, scheme="Token")` —
  the credential is a callable resolved per call, so nothing can cache one
  caller's token across requests, and the scheme is a parameter.
- `_request_token()` is the http-mode provider:
  `mcp.server.auth.middleware.auth_context.get_access_token()` (set by the
  SDK's `AuthContextMiddleware` for the request being served) → `.token`,
  raising if there is no authenticated request. stdio mode passes
  `Authenticator.token` (env or cache), unchanged.
- The 401→re-mint retry stays **stdio-only**, enforced structurally: http mode
  passes no `refresh` callable, so the retry branch cannot run. The MCP client
  must refresh its own token.
- Failures raise `EtipitakaAPIError` naming the request path and status but
  never the base URL, which in the deployed stack is an internal address. A
  401 says the token was rejected and should be refreshed. Both REST clients
  share this, since an unprovisioned canon edition returns 503 in normal
  operation and would otherwise leak the internal host.
- Canon tools call `CanonClient` with no token in both modes.
- Tool names, parameters and result shapes are **identical** in both modes.
- Isolation was verified end-to-end, not by inspection: two concurrent
  sessions with different bearers, driven from two threads, each forwarded
  its own caller's token, and the SDK independently rejects a session id
  replayed with a different bearer before any tool runs.

**Packaging / container (`pyproject.toml`, `Dockerfile`):**
- Add `uvicorn` to dependencies (the SDK's streamable-http runner uses it) and
  `anyio`, which `server.py` imports directly and whose thread-context
  behaviour carries the per-request token isolation.
- `mcp_server/requirements.txt` pins that runtime set exactly, as
  `app/requirements.txt` already does for Django. This matters more than usual
  because the security behaviour above rests on SDK internals verified by
  experiment rather than by a documented contract, and `deploy.sh` rebuilds on
  every deploy. The image installs the pinned set first, then the package with
  `--no-deps` so its open ranges cannot re-resolve over the pins.
- `mcp_server/Dockerfile`: a Debian-pinned `python:3.12-slim-bookworm`,
  unbuffered output, no bytecode, an unprivileged `USER`, `CMD
  ["etipitaka-mcp"]` with `ETIPITAKA_TRANSPORT=http` baked in (compose can
  still override). A `.dockerignore` keeps the virtualenv out of the build
  context, which took it from about 74 MB to 35 kB.

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
  - Rate limiting, per recovered client IP: `/mcp` at 10r/s burst 20, and a
    regex location covering both `/o/register` spellings at 6r/m burst 5,
    leaving the RFC 7592 management URLs beneath it unmetered. Throttled
    requests get a JSON body and a `Retry-After` hint rather than nginx's HTML
    page, scoped per location so Django's own login throttle is untouched.
  - `real_ip_header X-Forwarded-For` with `set_real_ip_from` limited to
    private ranges, so buckets key on the true client and a direct caller
    from a public address cannot spoof its way into another bucket.
  - `X-Forwarded-Proto` forwarded on every proxying location, preferring a
    value from the terminator and falling back to this proxy's own scheme.
- The `mcp` service carries a healthcheck probing its own unauthenticated
  protected-resource metadata, and nginx waits on it, so startup does not
  serve errors while the app is still importing.
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
- **Open DCR** cannot mint tokens by itself. Note that DOT's registration view
  is a plain Django view, so DRF throttle rates do **not** apply to it, and
  nginx has no `limit_req` today; rate limiting `/o/register/` and `/mcp` is a
  recorded follow-up (see Out of scope). The existing login throttle still
  protects `/login/`, which every token ultimately requires.
- **RFC 9700 posture is enforced, not just advertised:** DOT's
  `COMPLIANT_BCP_RFC9700_*` gates make PKCE S256-only, disable the implicit
  and password grants, accept tokens only in headers, and emit RFC 9207 `iss`;
  `REFRESH_TOKEN_REUSE_PROTECTION` revokes the whole token family when a
  rotated refresh token is replayed. Only DOT's base + DCR routes are mounted —
  its application-management UI and its own `/o/.well-known/*` documents are
  not exposed.
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
- `/.well-known/oauth-authorization-server` returns the exact metadata
  (issuer = `OIDC_ISS_ENDPOINT`, never the request host; all endpoints
  anchored on it; `S256` only; `etipitaka:read`; `response_types ["code"]`;
  `authorization_response_iss_parameter_supported: true`; `none` and
  `client_secret_basic` in the token/revocation auth methods).
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
- ~~Rate limiting on `/mcp` and `/o/register/`~~ — **done**, in nginx (see
  Component 4). It moved out of scope during review: a bogus bearer costs a
  Django round trip plus roughly two database transactions, because rejected
  tokens are deliberately never cached, so exposing `/mcp` publicly without a
  limit was not defensible.
- Hashed token storage at rest (`COMPLIANT_BCP_RFC9700_TOKEN_STORAGE`, DOT
  check W006) — deferred; evaluate against the direct-`AccessToken` test
  fixture before enabling.
- Periodic expiry cleanup (`manage.py cleartokens`) — with open DCR and 30-day
  refresh tokens the token tables grow until this is scheduled.
- Restricting the `client_credentials` and device-code grants server-side —
  they stay enabled inside DOT (and registrable via DCR); the metadata simply
  does not advertise them.
- Scoping `ng-app` in `base.html` to the pages that actually use AngularJS —
  until then every template that extends it and renders free text must opt
  out with `ng-non-bindable` (the consent page does).
- `registration_client_uri` in DCR responses is request-derived — **the code
  half is done**: nginx forwards `X-Forwarded-Proto` and Django trusts it
  behind an opt-in `TRUST_PROXY_PROTO`, default off, because a spoofable
  header must not be trusted by default. It is not cosmetic after all: that
  URL is returned beside a `registration_access_token`, so an `http://` value
  invites a bearer token over cleartext on the first hop. **Remaining
  operator step:** confirm the host-level TLS terminator sets both
  `X-Forwarded-Proto` and `X-Forwarded-For`, overwriting rather than passing
  client values, then enable the flag. See `docs/remote-mcp-oauth-deploy.md`,
  which also records why the published port was left bound to all interfaces.
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
