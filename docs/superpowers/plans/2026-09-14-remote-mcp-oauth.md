# Remote MCP Server with OAuth 2.1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the E-Tipitaka MCP server to mobile/remote clients over Streamable HTTP at `https://data.etipitaka.com/mcp`, protected by standards-based OAuth 2.1 (DCR + PKCE), while the existing local stdio server keeps working unchanged.

**Architecture:** Django + django-oauth-toolkit becomes the OAuth 2.1 Authorization Server (`/o/*`, RFC 8414 metadata at the site root). A new `mcp` container runs the same FastMCP tools over streamable-http as a pure Resource Server: it verifies each bearer token by calling Django's `/api/oauth/verify/` and forwards the caller's own token to `/api/content/*`, which now accepts OAuth bearers alongside DRF tokens. nginx routes `/mcp` and the protected-resource metadata to the new container. Spec: `docs/superpowers/specs/2026-09-14-remote-mcp-oauth-design.md`.

**Tech Stack:** Django 5.2 / DRF 3.16, **django-oauth-toolkit 3.4.1**, `mcp` SDK 1.30.0 (`mcp.server.auth`, streamable-http), httpx, uvicorn, Docker Compose, nginx 1.27. Tests: pytest-django (coverage gate 90 %), pytest + pytest-httpx + anyio (MCP), golden HTTP harness.

---

## File structure

**Django (Authorization Server + API)**
- Modify `app/requirements.txt` — add DOT.
- Modify `app/etipitaka_auth/settings.py` — `oauth2_provider` app, `OAUTH2_PROVIDER`, `OAUTH_ISSUER_URL`, `ALLOWED_HOSTS += ['web']`.
- Modify `app/etipitaka_auth/urls.py` — mount `/o/`, metadata + verify routes.
- Create `app/user_data/oauth_views.py` — RFC 8414 metadata view + `verify` view.
- Create `app/user_data/oauth_permissions.py` — `ScopedOrAuthenticated`.
- Modify `app/user_data/content_views.py` — accept OAuth bearers with scope check.
- Create `app/templates/oauth2_provider/authorize.html` — consent page.
- Modify `app/user_data/tests/conftest.py` — `make_oauth_token` helper + `oauth_alice` fixture.
- Create `app/user_data/tests/test_oauth.py` — AS + verify + flow + API tests.

**MCP (Resource Server)**
- Modify `mcp_server/etipitaka_mcp/config.py` — transport/http/issuer/resource/allowed-hosts.
- Create `mcp_server/etipitaka_mcp/verifier.py` — `DjangoTokenVerifier`.
- Modify `mcp_server/etipitaka_mcp/client.py` — `ContentClient` takes a token provider.
- Modify `mcp_server/etipitaka_mcp/server.py` — http-mode wiring, per-request token.
- Modify `mcp_server/pyproject.toml` — `uvicorn` dependency.
- Create `mcp_server/Dockerfile`.
- Create `mcp_server/tests/conftest.py` — anyio backend.
- Create `mcp_server/tests/test_verifier.py`, `mcp_server/tests/test_http_mode.py`.
- Modify `mcp_server/tests/test_client.py`, `test_config.py` — new signatures.

**Hosting / regression / docs**
- Modify `docker-compose.yml` — `mcp` service.
- Modify `nginx/nginx.conf` — `/mcp` + protected-resource routing.
- Modify `tests/golden/endpoints.py`, `tests/golden/README.md` + new snapshots.
- Create `tests/oauth_e2e.py` — hand-run end-to-end script.
- Modify `mcp_server/README.md`.

## Test environment notes

- Django tests run **in the container**: `docker compose exec -T web python -m pytest`. The prod image has no pytest; if `python -m pytest --version` fails, install once with `docker compose exec -u root -T -e PIP_DEFAULT_TIMEOUT=300 web pip install --retries 20 -r requirements-dev.txt` (PyPI has been flaky; CI installs fine).
- Task 1 changes `app/requirements.txt`, so **rebuild** the web image: `docker compose up -d --build web` (then reinstall dev deps as above if needed).
- MCP tests: `mcp_server/.venv/bin/python -m pytest mcp_server -q` (venv already exists).
- Golden: `tests/golden/.venv/bin/python -m pytest tests/golden --base-url http://localhost:1338` after `docker compose exec -T web python manage.py seed_golden`; golden **requires a fresh seed per run** (mutation cases).

---

### Task 1: Install django-oauth-toolkit as the Authorization Server (DCR + PKCE)

**Files:**
- Modify: `app/requirements.txt`
- Modify: `app/etipitaka_auth/settings.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_oauth.py`

- [ ] **Step 1: Write the failing DCR test**

Create `app/user_data/tests/test_oauth.py`:

```python
# -*- coding: utf-8 -*-
"""OAuth 2.1 Authorization Server (django-oauth-toolkit) + MCP resource support."""
import json

import pytest

DCR_BODY = {
    'client_name': 'test-client',
    'redirect_uris': ['https://app.example/cb'],
    'grant_types': ['authorization_code', 'refresh_token'],
    'response_types': ['code'],
    'token_endpoint_auth_method': 'none',
}


@pytest.mark.django_db
def test_dcr_registers_client(client):
    from oauth2_provider.models import Application
    resp = client.post('/o/register/', data=json.dumps(DCR_BODY),
                       content_type='application/json')
    assert resp.status_code == 201, resp.content
    body = resp.json()
    assert body['client_id']
    assert Application.objects.filter(client_id=body['client_id']).exists()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_oauth.py -q -o addopts=""`
Expected: FAIL — `ModuleNotFoundError: No module named 'oauth2_provider'` (or 404 on `/o/register/`).

- [ ] **Step 3: Add the dependency and settings**

`app/requirements.txt` — append:

```
django-oauth-toolkit==3.4.1
```

`app/etipitaka_auth/settings.py` — in `INSTALLED_APPS`, after `'rest_framework.authtoken',` add:

```python
    'oauth2_provider',
```

Change `ALLOWED_HOSTS` (the `mcp` container calls Django as `http://web:8000`):

```python
ALLOWED_HOSTS = ['data.etipitaka.com', '128.199.181.198', 'localhost', '127.0.0.1', 'web']
```

After the `REST_FRAMEWORK = {...}` block add:

```python
# OAuth 2.1 Authorization Server (django-oauth-toolkit) backing the remote MCP
# endpoint. Clients self-register (DCR), must use PKCE, and receive the single
# read-only scope. Issuer is the site root so RFC 8414 discovery lives at
# /.well-known/oauth-authorization-server.
OAUTH_ISSUER_URL = os.environ.get('OAUTH_ISSUER_URL', 'https://data.etipitaka.com')

OAUTH2_PROVIDER = {
    'SCOPES': {
        'etipitaka:read': 'Read your E-Tipitaka bookmarks, highlights, tags, '
                          'history and saved lexicon',
    },
    'DEFAULT_SCOPES': ['etipitaka:read'],
    'PKCE_REQUIRED': True,
    'DCR_ENABLED': True,
    'DCR_REGISTRATION_PERMISSION_CLASSES': (
        'oauth2_provider.dcr.AllowAllDCRPermission',
    ),
    # https covers web-callback clients (e.g. the Claude app); http covers
    # loopback redirects in dev. A client needing a custom scheme is onboarded
    # by appending it here.
    'ALLOWED_REDIRECT_URI_SCHEMES': ['https', 'http'],
    'ACCESS_TOKEN_EXPIRE_SECONDS': 3600,
    'REFRESH_TOKEN_EXPIRE_SECONDS': 30 * 24 * 3600,
    'ROTATE_REFRESH_TOKEN': True,
}
```

`app/etipitaka_auth/urls.py` — add after the `api/canon/dictionary/` line:

```python
    path('o/', include(('oauth2_provider.urls', 'oauth2_provider'), namespace='oauth2_provider')),
```

- [ ] **Step 4: Rebuild the web image, migrate, run the test**

Run:
```bash
docker compose up -d --build web
docker compose exec -T web python manage.py migrate --noinput
docker compose exec -T web python -m pytest --version || docker compose exec -u root -T -e PIP_DEFAULT_TIMEOUT=300 web pip install --retries 20 -r requirements-dev.txt
docker compose exec -T web python -m pytest user_data/tests/test_oauth.py -q -o addopts=""
```
Expected: `1 passed`. Migrate output lists `oauth2_provider` migrations applied.

- [ ] **Step 5: Smoke DCR over HTTP**

Run:
```bash
curl -s -X POST http://localhost:1338/o/register/ -H 'Content-Type: application/json' \
  -d '{"client_name":"smoke","redirect_uris":["https://example.com/cb"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}'
```
Expected: JSON containing `"client_id"` (HTTP 201).

- [ ] **Step 6: Commit**

```bash
git add app/requirements.txt app/etipitaka_auth/settings.py app/etipitaka_auth/urls.py app/user_data/tests/test_oauth.py
git commit -m "feat(oauth): install django-oauth-toolkit as authorization server (DCR, PKCE)"
```

---

### Task 2: RFC 8414 Authorization Server Metadata endpoint

**Files:**
- Create: `app/user_data/oauth_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Test: `app/user_data/tests/test_oauth.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_oauth.py`:

```python
def test_as_metadata(client, settings):
    settings.OAUTH_ISSUER_URL = 'https://issuer.example'
    resp = client.get('/.well-known/oauth-authorization-server')
    assert resp.status_code == 200
    body = resp.json()
    assert body['issuer'] == 'https://issuer.example'
    assert body['authorization_endpoint'] == 'https://issuer.example/o/authorize/'
    assert body['token_endpoint'] == 'https://issuer.example/o/token/'
    assert body['registration_endpoint'] == 'https://issuer.example/o/register/'
    assert body['revocation_endpoint'] == 'https://issuer.example/o/revoke_token/'
    assert body['scopes_supported'] == ['etipitaka:read']
    assert body['code_challenge_methods_supported'] == ['S256']
    assert body['grant_types_supported'] == ['authorization_code', 'refresh_token']
    assert 'none' in body['token_endpoint_auth_methods_supported']
```

- [ ] **Step 2: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_oauth.py::test_as_metadata -q -o addopts=""`
Expected: FAIL — 404.

- [ ] **Step 3: Implement the view**

Create `app/user_data/oauth_views.py`:

```python
# -*- coding: utf-8 -*-
"""OAuth support views: RFC 8414 server metadata and the resource-server
token check used by the remote MCP service."""
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes)
from rest_framework.permissions import IsAuthenticated

SCOPE = 'etipitaka:read'


@require_GET
def as_metadata(request):
    """RFC 8414 Authorization Server Metadata. The issuer is the site root."""
    base = settings.OAUTH_ISSUER_URL.rstrip('/')
    return JsonResponse({
        'issuer': base,
        'authorization_endpoint': base + '/o/authorize/',
        'token_endpoint': base + '/o/token/',
        'registration_endpoint': base + '/o/register/',
        'revocation_endpoint': base + '/o/revoke_token/',
        'scopes_supported': [SCOPE],
        'response_types_supported': ['code'],
        'grant_types_supported': ['authorization_code', 'refresh_token'],
        'code_challenge_methods_supported': ['S256'],
        'token_endpoint_auth_methods_supported': ['none', 'client_secret_post'],
    })
```

`app/etipitaka_auth/urls.py` — import and route:

```python
from user_data import oauth_views
```

add after the `o/` line:

```python
    path('.well-known/oauth-authorization-server', oauth_views.as_metadata),
```

- [ ] **Step 4: Run the test**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_oauth.py -q -o addopts=""`
Expected: `2 passed`.

- [ ] **Step 5: Commit**

```bash
git add app/user_data/oauth_views.py app/etipitaka_auth/urls.py app/user_data/tests/test_oauth.py
git commit -m "feat(oauth): RFC 8414 authorization-server metadata endpoint"
```

---

### Task 3: Token verify endpoint for the MCP resource server

**Files:**
- Modify: `app/user_data/oauth_views.py`
- Modify: `app/etipitaka_auth/urls.py`
- Modify: `app/user_data/tests/conftest.py`
- Test: `app/user_data/tests/test_oauth.py`

- [ ] **Step 1: Add the OAuth token helper to conftest**

Append to `app/user_data/tests/conftest.py`:

```python
def make_oauth_token(user, scope='etipitaka:read', seconds=3600):
    """Create a django-oauth-toolkit access token for `user` (public client)."""
    import secrets
    from datetime import timedelta
    from django.utils import timezone
    from oauth2_provider.models import AccessToken, Application
    app = Application.objects.create(
        name='test-app', client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris='https://app.example/cb')
    return AccessToken.objects.create(
        user=user, application=app, scope=scope,
        token='t-' + secrets.token_hex(16),
        expires=timezone.now() + timedelta(seconds=seconds))


@pytest.fixture
def oauth_alice(api, alice):
    """APIClient sending alice's OAuth bearer token with the read scope."""
    tok = make_oauth_token(alice)
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    return api
```

- [ ] **Step 2: Write the failing tests**

Append to `app/user_data/tests/test_oauth.py`:

```python
from .conftest import make_oauth_token


def test_verify_valid_token(api, alice):
    tok = make_oauth_token(alice)
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    resp = api.get('/api/oauth/verify/')
    assert resp.status_code == 200
    body = resp.json()
    assert body['active'] is True
    assert body['username'] == 'alice' and body['user_id'] == alice.pk
    assert body['scopes'] == ['etipitaka:read']
    assert body['client_id'] == tok.application.client_id
    assert isinstance(body['expires_at'], int)


def test_verify_bogus_token_401(api, db):
    api.credentials(HTTP_AUTHORIZATION='Bearer nope')
    assert api.get('/api/oauth/verify/').status_code == 401


def test_verify_expired_token_401(api, alice):
    tok = make_oauth_token(alice, seconds=-10)
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    assert api.get('/api/oauth/verify/').status_code == 401


def test_verify_reports_scopes_without_enforcing(api, alice):
    tok = make_oauth_token(alice, scope='')
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    resp = api.get('/api/oauth/verify/')
    assert resp.status_code == 200 and resp.json()['scopes'] == []
```

- [ ] **Step 3: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_oauth.py -q -o addopts=""`
Expected: 4 FAIL with 404.

- [ ] **Step 4: Implement the verify view**

Append to `app/user_data/oauth_views.py`:

```python
@api_view(['GET'])
@authentication_classes((OAuth2Authentication,))
@permission_classes((IsAuthenticated,))
def verify(request):
    """Token check for the MCP resource server.

    Reports the token's scopes but does NOT enforce them: the MCP SDK enforces
    its required scope (answering 403 insufficient_scope) and /api/content/*
    enforces it again independently.
    """
    tok = request.auth  # oauth2_provider.models.AccessToken
    return JsonResponse({
        'active': True,
        'username': request.user.username,
        'user_id': request.user.pk,
        'scopes': tok.scope.split(),
        'expires_at': int(tok.expires.timestamp()),
        'client_id': tok.application.client_id if tok.application else None,
    })
```

`app/etipitaka_auth/urls.py` — add after the metadata route:

```python
    path('api/oauth/verify/', oauth_views.verify),
```

- [ ] **Step 5: Run the tests**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_oauth.py -q -o addopts=""`
Expected: `6 passed`.

- [ ] **Step 6: Commit**

```bash
git add app/user_data/oauth_views.py app/etipitaka_auth/urls.py app/user_data/tests/conftest.py app/user_data/tests/test_oauth.py
git commit -m "feat(oauth): token verify endpoint for the MCP resource server"
```

---

### Task 4: Consent page + authorization-code/PKCE flow test

**Files:**
- Create: `app/templates/oauth2_provider/authorize.html`
- Test: `app/user_data/tests/test_oauth.py`

- [ ] **Step 1: Write the failing end-to-end flow test**

Append to `app/user_data/tests/test_oauth.py`:

```python
import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse


def _pkce():
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


@pytest.mark.django_db
def test_authorization_code_pkce_flow(client, alice):
    reg = client.post('/o/register/', data=json.dumps(DCR_BODY),
                      content_type='application/json').json()
    cid = reg['client_id']
    verifier, challenge = _pkce()
    params = {
        'response_type': 'code', 'client_id': cid,
        'redirect_uri': 'https://app.example/cb', 'scope': 'etipitaka:read',
        'state': 'xyz', 'code_challenge': challenge,
        'code_challenge_method': 'S256',
    }
    # Anonymous -> redirected to the site login page.
    anon = client.get('/o/authorize/', params)
    assert anon.status_code == 302 and anon['Location'].startswith('/login/')

    client.force_login(alice)
    page = client.get('/o/authorize/', params)
    assert page.status_code == 200
    assert b'test-client' in page.content and b'name="allow"' in page.content

    allowed = client.post('/o/authorize/', {**params, 'allow': 'Authorize'})
    assert allowed.status_code == 302
    loc = urlparse(allowed['Location'])
    assert loc.netloc == 'app.example'
    qs = parse_qs(loc.query)
    assert qs['state'] == ['xyz']
    code = qs['code'][0]

    tok = client.post('/o/token/', {
        'grant_type': 'authorization_code', 'code': code,
        'redirect_uri': 'https://app.example/cb', 'client_id': cid,
        'code_verifier': verifier,
    })
    assert tok.status_code == 200, tok.content
    body = tok.json()
    assert body['token_type'].lower() == 'bearer'
    assert body['scope'] == 'etipitaka:read'
    assert body['access_token'] and body['refresh_token']

    # The issued token is accepted by the verify endpoint.
    ok = client.get('/api/oauth/verify/',
                    HTTP_AUTHORIZATION='Bearer ' + body['access_token'])
    assert ok.status_code == 200 and ok.json()['username'] == 'alice'
```

- [ ] **Step 2: Run it to verify it fails**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_oauth.py::test_authorization_code_pkce_flow -q -o addopts=""`
Expected: FAIL — the consent page assertion (`name="allow"` / client name) fails against DOT's default template or the template is missing.

- [ ] **Step 3: Add the consent template**

Create `app/templates/oauth2_provider/authorize.html`:

```django
{% extends 'base.html' %}
{% load i18n %}

{% block title %}{% trans "Authorize application" %}{% endblock %}

{% block body %}
<div class="container">
  {% if not error %}
  <h1>{% blocktrans with name=application.name %}Allow "{{ name }}" to access your E-Tipitaka data?{% endblocktrans %}</h1>
  <p>{% trans "The application will be able to:" %}</p>
  <ul>
    {% for scope in scopes_descriptions %}<li>{{ scope }}</li>{% endfor %}
  </ul>
  <form method="post" action="{% url 'oauth2_provider:authorize' %}">
    {% csrf_token %}
    {% for field in form %}{% if field.is_hidden %}{{ field }}{% endif %}{% endfor %}
    <button type="submit" class="btn btn-primary" name="allow" value="Authorize">{% trans "Allow" %}</button>
    <button type="submit" class="btn btn-default">{% trans "Deny" %}</button>
  </form>
  {% else %}
  <h1>{% trans "Error" %}: {{ error.error }}</h1>
  <p>{{ error.description }}</p>
  {% endif %}
</div>
{% endblock %}
```

- [ ] **Step 4: Run the tests**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_oauth.py -q -o addopts=""`
Expected: `7 passed`.

- [ ] **Step 5: Commit**

```bash
git add app/templates/oauth2_provider/authorize.html app/user_data/tests/test_oauth.py
git commit -m "feat(oauth): consent page and authorization-code PKCE flow test"
```

---

### Task 5: `/api/content/*` accepts OAuth bearer tokens with scope check

**Files:**
- Create: `app/user_data/oauth_permissions.py`
- Modify: `app/user_data/content_views.py`
- Test: `app/user_data/tests/test_oauth.py`

- [ ] **Step 1: Write the failing tests**

Append to `app/user_data/tests/test_oauth.py`:

```python
from .conftest import make_content_db  # fixtures (media_tmp, canon_dir) auto-load from conftest

BOOKMARK_SQL = ("CREATE TABLE bookmark (created FLOAT, important INTEGER, note TEXT, "
                "rank INTEGER, code INTEGER, volume INTEGER, page INTEGER)")


def _seed_bookmarks(alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SQL,
                    [(1457843335.0, 1, 'n', 0, 1, 10, 101)])


def test_content_accepts_oauth_bearer(oauth_alice, alice, media_tmp):
    _seed_bookmarks(alice)
    resp = oauth_alice.get('/api/content/bookmarks/')
    assert resp.status_code == 200 and resp.json()['count'] == 1


def test_content_oauth_without_scope_403(api, alice, media_tmp):
    tok = make_oauth_token(alice, scope='')
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    assert api.get('/api/content/bookmarks/').status_code == 403


def test_content_drf_token_still_works(auth_alice, alice, media_tmp):
    _seed_bookmarks(alice)
    assert auth_alice.get('/api/content/bookmarks/').status_code == 200


def test_content_anonymous_still_401(api, db):
    assert api.get('/api/content/bookmarks/').status_code == 401


def test_summary_accepts_oauth_bearer(oauth_alice):
    assert oauth_alice.get('/api/content/summary/').status_code == 200


def test_canon_still_public(api, canon_dir):
    assert api.get('/api/canon/editions/').status_code == 200
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_oauth.py -q -o addopts=""`
Expected: `test_content_accepts_oauth_bearer`, `test_content_oauth_without_scope_403`, `test_summary_accepts_oauth_bearer` FAIL (401 — bearer not recognised); the rest pass.

- [ ] **Step 3: Implement the permission and wire the views**

Create `app/user_data/oauth_permissions.py`:

```python
# -*- coding: utf-8 -*-
from rest_framework.permissions import BasePermission

SCOPE = 'etipitaka:read'


class ScopedOrAuthenticated(BasePermission):
    """OAuth access tokens must carry `etipitaka:read`; DRF tokens and
    sessions only need to be authenticated (unchanged behaviour).

    django-oauth-toolkit's TokenHasScope cannot be used directly: it asserts
    when the request was authenticated by anything other than OAuth2, which
    would break the existing DRF-token clients.
    """

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        token = request.auth
        if hasattr(token, 'scope'):  # oauth2_provider.models.AccessToken
            return token.is_valid([SCOPE])
        return True
```

`app/user_data/content_views.py` — replace the imports:

```python
from django.http import JsonResponse
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes)
from rest_framework.authentication import TokenAuthentication, SessionAuthentication

from .oauth_permissions import ScopedOrAuthenticated
from .sqlite_reader import read_table
```

and change **both** decorator stacks (in `_content_endpoint` and on `summary`) to:

```python
    @api_view(['GET'])
    @authentication_classes((OAuth2Authentication, TokenAuthentication,
                             SessionAuthentication))
    @permission_classes((ScopedOrAuthenticated,))
```

(`summary` uses the same three decorators without the leading indentation.)

- [ ] **Step 4: Run the OAuth tests, then the full Django suite with the coverage gate**

Run: `docker compose exec -T web python -m pytest user_data/tests/test_oauth.py -q -o addopts=""`
Expected: `13 passed`.

Run: `docker compose exec -T web python -m pytest -q`
Expected: all pass (previously 123 + 13 new), `Required test coverage of 90% reached`.

- [ ] **Step 5: Commit**

```bash
git add app/user_data/oauth_permissions.py app/user_data/content_views.py app/user_data/tests/test_oauth.py
git commit -m "feat(api): accept OAuth bearer tokens on /api/content with scope check"
```

---

### Task 6: MCP config — transport and http-mode settings

**Files:**
- Modify: `mcp_server/etipitaka_mcp/config.py`
- Modify: `mcp_server/tests/test_config.py`

- [ ] **Step 1: Write the failing tests**

Replace `mcp_server/tests/test_config.py` with:

```python
from etipitaka_mcp.config import load_config

ALL_VARS = ['ETIPITAKA_BASE_URL', 'ETIPITAKA_USERNAME', 'ETIPITAKA_PASSWORD',
            'ETIPITAKA_TOKEN', 'ETIPITAKA_DEFAULT_EDITION', 'ETIPITAKA_TRANSPORT',
            'ETIPITAKA_ISSUER_URL', 'ETIPITAKA_RESOURCE_URL', 'ETIPITAKA_HTTP_HOST',
            'ETIPITAKA_HTTP_PORT', 'ETIPITAKA_ALLOWED_HOSTS']


def test_defaults(monkeypatch):
    for var in ALL_VARS:
        monkeypatch.delenv(var, raising=False)
    cfg = load_config()
    assert cfg.base_url == 'https://data.etipitaka.com'
    assert cfg.username is None and cfg.token is None
    assert cfg.default_edition is None
    assert cfg.transport == 'stdio'
    assert cfg.issuer_url is None and cfg.resource_url is None
    assert cfg.http_host == '0.0.0.0' and cfg.http_port == 8001
    assert cfg.allowed_hosts == ['localhost:*', '127.0.0.1:*']


def test_reads_env(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_BASE_URL', 'http://localhost:1338')
    monkeypatch.setenv('ETIPITAKA_USERNAME', 'alice')
    monkeypatch.setenv('ETIPITAKA_DEFAULT_EDITION', 'thai')
    monkeypatch.setenv('ETIPITAKA_TRANSPORT', 'http')
    monkeypatch.setenv('ETIPITAKA_ISSUER_URL', 'https://as.example')
    monkeypatch.setenv('ETIPITAKA_RESOURCE_URL', 'https://rs.example/mcp')
    monkeypatch.setenv('ETIPITAKA_HTTP_PORT', '9000')
    monkeypatch.setenv('ETIPITAKA_ALLOWED_HOSTS', 'rs.example, localhost:*')
    cfg = load_config()
    assert cfg.base_url == 'http://localhost:1338'
    assert cfg.username == 'alice'
    assert cfg.default_edition == 'thai'
    assert cfg.transport == 'http'
    assert cfg.issuer_url == 'https://as.example'
    assert cfg.resource_url == 'https://rs.example/mcp'
    assert cfg.http_port == 9000
    assert cfg.allowed_hosts == ['rs.example', 'localhost:*']
```

- [ ] **Step 2: Run them to verify they fail**

Run: `mcp_server/.venv/bin/python -m pytest mcp_server/tests/test_config.py -q`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'transport'`.

- [ ] **Step 3: Implement the config**

Replace `mcp_server/etipitaka_mcp/config.py` with:

```python
import os
from dataclasses import dataclass, field


@dataclass
class Config:
    base_url: str
    username: str | None
    password: str | None
    token: str | None
    default_edition: str | None
    transport: str = 'stdio'            # 'stdio' | 'http'
    issuer_url: str | None = None       # public OAuth issuer (http mode)
    resource_url: str | None = None     # public URL of this MCP endpoint (http mode)
    http_host: str = '0.0.0.0'
    http_port: int = 8001
    allowed_hosts: list[str] = field(default_factory=list)


def _csv(value):
    return [h.strip() for h in value.split(',') if h.strip()]


def load_config():
    return Config(
        base_url=os.environ.get('ETIPITAKA_BASE_URL', 'https://data.etipitaka.com'),
        username=os.environ.get('ETIPITAKA_USERNAME'),
        password=os.environ.get('ETIPITAKA_PASSWORD'),
        token=os.environ.get('ETIPITAKA_TOKEN'),
        default_edition=os.environ.get('ETIPITAKA_DEFAULT_EDITION'),
        transport=os.environ.get('ETIPITAKA_TRANSPORT', 'stdio'),
        issuer_url=os.environ.get('ETIPITAKA_ISSUER_URL'),
        resource_url=os.environ.get('ETIPITAKA_RESOURCE_URL'),
        http_host=os.environ.get('ETIPITAKA_HTTP_HOST', '0.0.0.0'),
        http_port=int(os.environ.get('ETIPITAKA_HTTP_PORT', '8001')),
        # Hosts the SDK's DNS-rebinding protection accepts; nginx forwards the
        # original Host header, so production adds its public hostname.
        allowed_hosts=_csv(os.environ.get('ETIPITAKA_ALLOWED_HOSTS',
                                          'localhost:*,127.0.0.1:*')),
    )
```

- [ ] **Step 4: Run the tests**

Run: `mcp_server/.venv/bin/python -m pytest mcp_server/tests/test_config.py -q`
Expected: `2 passed`.

- [ ] **Step 5: Commit**

```bash
git add mcp_server/etipitaka_mcp/config.py mcp_server/tests/test_config.py
git commit -m "feat(mcp): transport and http-mode configuration"
```

---

### Task 7: `DjangoTokenVerifier` (resource-server token check, 60 s cache)

**Files:**
- Create: `mcp_server/etipitaka_mcp/verifier.py`
- Create: `mcp_server/tests/conftest.py`
- Test: `mcp_server/tests/test_verifier.py`

- [ ] **Step 1: Add the anyio backend fixture**

Create `mcp_server/tests/conftest.py`:

```python
import pytest


@pytest.fixture
def anyio_backend():
    # The mcp SDK brings anyio (and its pytest plugin); run async tests on
    # asyncio only so trio need not be installed.
    return 'asyncio'
```

- [ ] **Step 2: Write the failing tests**

Create `mcp_server/tests/test_verifier.py`:

```python
import httpx
import pytest

from etipitaka_mcp.verifier import DjangoTokenVerifier

pytestmark = pytest.mark.anyio

VERIFY_URL = 'http://d/api/oauth/verify/'
OK_BODY = {'active': True, 'username': 'alice', 'user_id': 1,
           'scopes': ['etipitaka:read'], 'expires_at': 4102444800,
           'client_id': 'cid-1'}


async def test_valid_token_returns_access_token(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, json=OK_BODY)
    tok = await DjangoTokenVerifier('http://d/').verify_token('abc')
    assert tok is not None
    assert tok.token == 'abc'
    assert tok.scopes == ['etipitaka:read']
    assert tok.client_id == 'cid-1'
    assert tok.expires_at == 4102444800
    req = httpx_mock.get_requests()[0]
    assert req.headers['Authorization'] == 'Bearer abc'


async def test_rejected_token_is_none(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, status_code=401)
    assert await DjangoTokenVerifier('http://d').verify_token('bad') is None


async def test_network_error_is_none(httpx_mock):
    httpx_mock.add_exception(httpx.ConnectError('down'))
    assert await DjangoTokenVerifier('http://d').verify_token('x') is None


async def test_cache_hit_skips_second_request(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, json=OK_BODY)
    v = DjangoTokenVerifier('http://d')
    first = await v.verify_token('abc')
    second = await v.verify_token('abc')
    assert first is second
    assert len(httpx_mock.get_requests()) == 1


async def test_negative_result_not_cached(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, status_code=401)
    httpx_mock.add_response(url=VERIFY_URL, json=OK_BODY)
    v = DjangoTokenVerifier('http://d')
    assert await v.verify_token('abc') is None
    assert (await v.verify_token('abc')) is not None
```

- [ ] **Step 3: Run them to verify they fail**

Run: `mcp_server/.venv/bin/python -m pytest mcp_server/tests/test_verifier.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'etipitaka_mcp.verifier'`.

- [ ] **Step 4: Implement the verifier**

Create `mcp_server/etipitaka_mcp/verifier.py`:

```python
"""OAuth resource-server token check.

The remote MCP server never issues tokens; it asks Django whether the bearer
token it received is valid by forwarding that token to /api/oauth/verify/.
"""
import hashlib
import logging
import time

import httpx
from mcp.server.auth.provider import AccessToken

log = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 60
CACHE_MAX_ENTRIES = 512


class DjangoTokenVerifier:
    """Implements the mcp TokenVerifier protocol against the Django verify endpoint."""

    def __init__(self, base_url, timeout=10):
        self.url = base_url.rstrip('/') + '/api/oauth/verify/'
        self.timeout = timeout
        self._cache = {}  # sha256(token) -> (expires_monotonic, AccessToken)

    async def verify_token(self, token: str) -> AccessToken | None:
        key = hashlib.sha256(token.encode()).hexdigest()
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    self.url, headers={'Authorization': 'Bearer ' + token})
        except httpx.HTTPError as exc:
            log.warning('token verify failed (%s) for %s…', exc, key[:8])
            return None
        if resp.status_code != 200:
            return None
        body = resp.json()
        access = AccessToken(
            token=token,
            client_id=body.get('client_id') or '',
            scopes=list(body.get('scopes') or []),
            expires_at=body.get('expires_at'),
        )
        if len(self._cache) >= CACHE_MAX_ENTRIES:
            self._cache.clear()
        self._cache[key] = (now + CACHE_TTL_SECONDS, access)
        return access
```

- [ ] **Step 5: Run the tests**

Run: `mcp_server/.venv/bin/python -m pytest mcp_server/tests/test_verifier.py -q`
Expected: `5 passed`.

- [ ] **Step 6: Commit**

```bash
git add mcp_server/etipitaka_mcp/verifier.py mcp_server/tests/conftest.py mcp_server/tests/test_verifier.py
git commit -m "feat(mcp): DjangoTokenVerifier with short-lived cache"
```

---

### Task 8: Streamable-http resource server + per-request token forwarding

**Files:**
- Modify: `mcp_server/etipitaka_mcp/client.py`
- Modify: `mcp_server/etipitaka_mcp/server.py`
- Modify: `mcp_server/tests/test_client.py`
- Test: `mcp_server/tests/test_http_mode.py`

- [ ] **Step 1: Update the client tests to the token-provider signature**

In `mcp_server/tests/test_client.py` replace the two `ContentClient` tests:

```python
def test_get_sends_token_and_drops_none_params(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/api/content/bookmarks/?volume=10',
                            json={'items': [], 'count': 0})
    auth = _auth(tmp_path)
    client = ContentClient('http://x', auth.token)
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
    client = ContentClient('http://x', auth.token,
                           refresh=lambda: auth.token(refresh=True))
    assert client.get_summary() == {'ok': True}


def test_bearer_scheme_without_refresh_raises_on_401(httpx_mock):
    httpx_mock.add_response(url='http://x/api/content/summary/', status_code=401)
    client = ContentClient('http://x', lambda: 'ACCESS', scheme='Bearer')
    with pytest.raises(httpx.HTTPStatusError):
        client.get_summary()
    assert httpx_mock.get_requests()[0].headers['Authorization'] == 'Bearer ACCESS'
```

Add at the top of the file:

```python
import httpx
import pytest
```

- [ ] **Step 2: Write the failing http-mode tests**

Create `mcp_server/tests/test_http_mode.py`:

```python
import importlib
import re
from urllib.parse import urlparse

import pytest
from starlette.testclient import TestClient

HTTP_ENV = {
    'ETIPITAKA_TRANSPORT': 'http',
    'ETIPITAKA_BASE_URL': 'http://django.test',
    'ETIPITAKA_ISSUER_URL': 'https://as.example',
    'ETIPITAKA_RESOURCE_URL': 'https://rs.example/mcp',
    'ETIPITAKA_ALLOWED_HOSTS': 'testserver,testserver:*',
}


@pytest.fixture
def http_server(monkeypatch):
    for k, v in HTTP_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv('ETIPITAKA_TOKEN', raising=False)
    import etipitaka_mcp.server as srv
    return importlib.reload(srv)


def test_unauthenticated_mcp_call_gets_401_with_resource_metadata(http_server):
    with TestClient(http_server.mcp.streamable_http_app()) as c:
        r = c.post('/mcp', json={'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'},
                   headers={'Accept': 'application/json, text/event-stream'})
        assert r.status_code == 401
        www = r.headers['WWW-Authenticate']
        m = re.search(r'resource_metadata="([^"]+)"', www)
        assert m, www
        meta = c.get(urlparse(m.group(1)).path)
        assert meta.status_code == 200
        body = meta.json()
        assert body['authorization_servers'][0].startswith('https://as.example')
        assert body['resource'].startswith('https://rs.example/mcp')
        assert 'etipitaka:read' in body['scopes_supported']


def test_http_mode_requires_issuer_and_resource(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_TRANSPORT', 'http')
    monkeypatch.delenv('ETIPITAKA_ISSUER_URL', raising=False)
    monkeypatch.delenv('ETIPITAKA_RESOURCE_URL', raising=False)
    import etipitaka_mcp.server as srv
    with pytest.raises(SystemExit):
        importlib.reload(srv)


def test_request_token_requires_auth_context(http_server):
    with pytest.raises(ValueError):
        http_server._request_token()


def test_stdio_mode_unaffected(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_TRANSPORT', 'stdio')
    monkeypatch.setenv('ETIPITAKA_TOKEN', 'TOK')
    import etipitaka_mcp.server as srv
    srv = importlib.reload(srv)
    assert srv.cfg.transport == 'stdio'
    assert srv._content.scheme == 'Token'
```

- [ ] **Step 3: Run them to verify they fail**

Run: `mcp_server/.venv/bin/python -m pytest mcp_server/tests/test_client.py mcp_server/tests/test_http_mode.py -q`
Expected: FAIL — `TypeError` on the new `ContentClient` signature / `AttributeError: _request_token`.

- [ ] **Step 4: Implement the client change**

Replace the `ContentClient` class in `mcp_server/etipitaka_mcp/client.py` (keep `CanonClient` as is):

```python
class ContentClient:
    """Calls the Django Content REST API with a caller-supplied credential.

    `token_provider()` returns the credential for the current call: in stdio
    mode the user's DRF token (scheme "Token"); in http mode the OAuth bearer
    of the request being served (scheme "Bearer"). `refresh()` optionally
    re-mints once on 401 (stdio only); when absent a 401 is raised.
    """

    def __init__(self, base_url, token_provider, refresh=None, scheme='Token',
                 timeout=30):
        self.base_url = base_url.rstrip('/')
        self.token_provider = token_provider
        self.refresh = refresh
        self.scheme = scheme
        self.timeout = timeout

    def _headers(self, token):
        return {'Authorization': '%s %s' % (self.scheme, token)}

    def _get(self, path, params=None):
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        url = self.base_url + path
        resp = httpx.get(url, params=clean, headers=self._headers(self.token_provider()),
                         timeout=self.timeout)
        if resp.status_code == 401 and self.refresh is not None:
            resp = httpx.get(url, params=clean, headers=self._headers(self.refresh()),
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

- [ ] **Step 5: Implement the server wiring**

In `mcp_server/etipitaka_mcp/server.py` replace everything from the top of the file down to (but not including) the `# --- personal data (plain impls) ---` line with:

```python
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .auth import Authenticator
from .client import CanonClient, ContentClient
from .config import load_config
from .verifier import DjangoTokenVerifier

REQUIRED_SCOPE = 'etipitaka:read'

cfg = load_config()


def _request_token():
    """Bearer token of the MCP request currently being served (http mode)."""
    access = get_access_token()
    if access is None:
        raise ValueError('no authenticated request token')
    return access.token


if cfg.transport == 'http':
    if not (cfg.issuer_url and cfg.resource_url):
        raise SystemExit('ETIPITAKA_TRANSPORT=http needs ETIPITAKA_ISSUER_URL '
                         'and ETIPITAKA_RESOURCE_URL')
    # Resource server: the SDK validates bearer tokens via the verifier,
    # answers unauthenticated calls with 401 + WWW-Authenticate, enforces the
    # scope, and publishes RFC 9728 metadata naming the issuer.
    mcp = FastMCP(
        'etipitaka',
        auth=AuthSettings(
            issuer_url=cfg.issuer_url,
            resource_server_url=cfg.resource_url,
            required_scopes=[REQUIRED_SCOPE],
            # v1 relies on scope + issuer; DOT tokens carry no resource claim.
            validate_token_resource=False,
        ),
        token_verifier=DjangoTokenVerifier(cfg.base_url),
        host=cfg.http_host,
        port=cfg.http_port,
        streamable_http_path='/mcp',
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=cfg.allowed_hosts),
    )
    _content = ContentClient(cfg.base_url, _request_token, scheme='Bearer')
else:
    mcp = FastMCP('etipitaka')
    _auth = Authenticator(cfg.base_url, cfg.username, cfg.password, cfg.token)
    _content = ContentClient(cfg.base_url, _auth.token,
                             refresh=lambda: _auth.token(refresh=True))

_canon = CanonClient(cfg.base_url)
```

and replace `main()` at the bottom with:

```python
def main():
    mcp.run(transport='streamable-http' if cfg.transport == 'http' else 'stdio')
```

- [ ] **Step 6: Run the whole MCP suite**

Run: `mcp_server/.venv/bin/python -m pytest mcp_server -q`
Expected: `29 passed` (the 19 pre-existing tests, with `test_config` replaced 2-for-2 in Task 6, + 5 verifier + 1 new client test + 4 http-mode).

- [ ] **Step 7: Commit**

```bash
git add mcp_server/etipitaka_mcp/client.py mcp_server/etipitaka_mcp/server.py mcp_server/tests/test_client.py mcp_server/tests/test_http_mode.py
git commit -m "feat(mcp): streamable-http resource server with per-request token forwarding"
```

---

### Task 9: Packaging — uvicorn dependency and container image

**Files:**
- Modify: `mcp_server/pyproject.toml`
- Create: `mcp_server/Dockerfile`

- [ ] **Step 1: Add the dependency**

In `mcp_server/pyproject.toml` change the dependencies line to:

```toml
dependencies = ["mcp>=1.2.0,<2", "httpx>=0.27", "uvicorn>=0.30"]
```

- [ ] **Step 2: Create the Dockerfile**

Create `mcp_server/Dockerfile`:

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY etipitaka_mcp ./etipitaka_mcp
RUN pip install --no-cache-dir .

# Runs the remote (streamable-http) resource server; compose supplies the
# ETIPITAKA_* environment. Local stdio use never touches this image.
ENV ETIPITAKA_TRANSPORT=http
EXPOSE 8001
CMD ["etipitaka-mcp"]
```

- [ ] **Step 3: Verify the editable install still resolves and the image builds**

Run:
```bash
mcp_server/.venv/bin/pip install -e mcp_server -q && mcp_server/.venv/bin/python -m pytest mcp_server -q
docker build -t etipitaka-mcp-test mcp_server
```
Expected: tests pass; `docker build` succeeds (PyPI may be slow — retry if it times out).

- [ ] **Step 4: Commit**

```bash
git add mcp_server/pyproject.toml mcp_server/Dockerfile
git commit -m "build(mcp): uvicorn dependency and container image for the remote server"
```

---

### Task 10: Hosting — `mcp` service in compose and nginx routing

**Files:**
- Modify: `docker-compose.yml`
- Modify: `nginx/nginx.conf`

- [ ] **Step 1: Add the service**

In `docker-compose.yml` add after the `web` service (before `db:`):

```yaml
  mcp:
    build:
      context: ./mcp_server
    expose:
      - 8001
    environment:
      ETIPITAKA_TRANSPORT: http
      # Internal Django for verify + API calls; public URLs for OAuth metadata.
      ETIPITAKA_BASE_URL: http://web:8000
      ETIPITAKA_ISSUER_URL: https://data.etipitaka.com
      ETIPITAKA_RESOURCE_URL: https://data.etipitaka.com/mcp
      # nginx forwards the original Host header; allow prod + local dev/golden.
      ETIPITAKA_ALLOWED_HOSTS: data.etipitaka.com,data.etipitaka.com:*,localhost:*,127.0.0.1:*
    depends_on:
      - web
```

and add `- mcp` to the nginx service's `depends_on` list.

- [ ] **Step 2: Route in nginx**

Replace `nginx/nginx.conf` with:

```nginx
upstream app {
    server web:8000;
}

upstream mcp {
    server mcp:8001;
}

server {

    listen 80;

    client_max_body_size 0;

    location / {
        proxy_pass http://app;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;
    }

    # Remote MCP endpoint (Streamable HTTP holds long-lived responses/SSE).
    location /mcp {
        proxy_pass http://mcp;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600;
    }

    # RFC 9728 protected-resource metadata is published by the MCP service.
    location /.well-known/oauth-protected-resource {
        proxy_pass http://mcp;
        proxy_set_header Host $http_host;
    }

    location /static/ {
        alias /home/app/web/static/;
    }

    location /media/ {
        alias /home/app/web/media/;
    }

}
```

- [ ] **Step 3: Bring the stack up and smoke the routing**

Run:
```bash
docker compose up -d --build
sleep 5
curl -s -o /dev/null -w 'mcp unauth: %{http_code}\n' -X POST http://localhost:1338/mcp -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d '{}'
curl -s http://localhost:1338/.well-known/oauth-protected-resource/mcp; echo
curl -s http://localhost:1338/.well-known/oauth-authorization-server; echo
curl -s -o /dev/null -w 'canon still public: %{http_code}\n' http://localhost:1338/api/canon/editions/
```
Expected: `mcp unauth: 401`; the protected-resource JSON with `"authorization_servers": ["https://data.etipitaka.com/"]`; the AS metadata JSON with `"issuer": "https://data.etipitaka.com"`; `canon still public: 200`.

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml nginx/nginx.conf
git commit -m "infra: mcp service in compose and nginx routing for /mcp and OAuth metadata"
```

---

### Task 11: Golden cases for OAuth / MCP discovery

**Files:**
- Modify: `tests/golden/endpoints.py`
- Modify: `tests/golden/README.md`
- Create: `tests/golden/snapshots/oauth_as_metadata.json`, `mcp_resource_metadata.json`, `mcp_unauthenticated.json` (recorded)

- [ ] **Step 1: Add the cases**

In `tests/golden/endpoints.py` add after the canon block:

```python
    # --- OAuth / remote MCP discovery (same-stack; deterministic JSON) ---
    GoldenCase("oauth_as_metadata", "GET", "/.well-known/oauth-authorization-server"),
    GoldenCase("mcp_resource_metadata", "GET", "/.well-known/oauth-protected-resource/mcp"),
    GoldenCase("mcp_unauthenticated", "POST", "/mcp"),
```

- [ ] **Step 2: Document them**

In `tests/golden/README.md` add to the localization/same-stack list:

```markdown
- The OAuth / remote-MCP discovery snapshots (`oauth_as_metadata`,
  `mcp_resource_metadata`, `mcp_unauthenticated`) are same-stack — the
  authorization server and the `mcp` service did not exist on the old stack.
  They advertise the canonical production issuer (`OAUTH_ISSUER_URL`,
  default `https://data.etipitaka.com`) regardless of the host under test.
```

- [ ] **Step 3: Record, then assert on a fresh seed**

Run:
```bash
docker compose exec -T web python manage.py seed_golden
tests/golden/.venv/bin/python -m pytest tests/golden/test_golden.py -k "oauth or mcp_" --record --base-url http://localhost:1338 -q
docker compose exec -T web python manage.py seed_golden
tests/golden/.venv/bin/python -m pytest tests/golden --base-url http://localhost:1338 -q
```
Expected: 3 snapshots written; full suite `45 passed`.

- [ ] **Step 4: Commit**

```bash
git add tests/golden/endpoints.py tests/golden/README.md tests/golden/snapshots/oauth_as_metadata.json tests/golden/snapshots/mcp_resource_metadata.json tests/golden/snapshots/mcp_unauthenticated.json
git commit -m "test(golden): OAuth and remote-MCP discovery cases"
```

---

### Task 12: End-to-end script and docs

**Files:**
- Create: `tests/oauth_e2e.py`
- Modify: `mcp_server/README.md`

- [ ] **Step 1: Write the end-to-end script**

Create `tests/oauth_e2e.py`:

```python
"""End-to-end check of the remote MCP OAuth flow against a running stack.

Run by hand (needs the golden seed users):
    docker compose exec -T web python manage.py seed_golden
    mcp_server/.venv/bin/python tests/oauth_e2e.py http://localhost:1338

Flow: DCR -> web login -> consent -> code -> token -> MCP initialize +
tools/list + whoami over Streamable HTTP with the bearer token.
"""
import asyncio
import base64
import hashlib
import secrets
import sys
from urllib.parse import parse_qs, urlparse

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

USERNAME, PASSWORD = 'alice', 'alicepass123'
REDIRECT = 'https://app.example/cb'


def pkce():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    return verifier, challenge


def get_token(base):
    s = httpx.Client(base_url=base, follow_redirects=False, timeout=30)
    reg = s.post('/o/register/', json={
        'client_name': 'e2e', 'redirect_uris': [REDIRECT],
        'grant_types': ['authorization_code', 'refresh_token'],
        'response_types': ['code'], 'token_endpoint_auth_method': 'none'})
    reg.raise_for_status()
    cid = reg.json()['client_id']
    print('DCR client_id:', cid)

    s.get('/login/')
    csrf = s.cookies['csrftoken']
    login = s.post('/login/', data={'username': USERNAME, 'password': PASSWORD,
                                    'csrfmiddlewaretoken': csrf},
                   headers={'Referer': base + '/login/'})
    assert login.status_code in (302, 200), login.status_code
    assert 'sessionid' in s.cookies, 'login failed'
    print('logged in as', USERNAME)

    verifier, challenge = pkce()
    params = {'response_type': 'code', 'client_id': cid, 'redirect_uri': REDIRECT,
              'scope': 'etipitaka:read', 'state': 's1',
              'code_challenge': challenge, 'code_challenge_method': 'S256'}
    page = s.get('/o/authorize/', params=params)
    assert page.status_code == 200 and 'name="allow"' in page.text, page.status_code
    csrf = s.cookies['csrftoken']
    allowed = s.post('/o/authorize/', data={**params, 'allow': 'Authorize',
                                            'csrfmiddlewaretoken': csrf},
                     headers={'Referer': base + '/o/authorize/'})
    assert allowed.status_code == 302, allowed.status_code
    code = parse_qs(urlparse(allowed.headers['location']).query)['code'][0]
    print('consent granted, code obtained')

    tok = s.post('/o/token/', data={'grant_type': 'authorization_code', 'code': code,
                                    'redirect_uri': REDIRECT, 'client_id': cid,
                                    'code_verifier': verifier})
    tok.raise_for_status()
    access = tok.json()['access_token']
    print('access token issued (scope:', tok.json()['scope'] + ')')
    return access


async def call_mcp(base, access):
    async with streamablehttp_client(
            base + '/mcp', headers={'Authorization': 'Bearer ' + access}) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            print('tools:', names)
            assert 'whoami' in names and 'search_canon' in names
            who = await session.call_tool('whoami', {})
            print('whoami:', who.content[0].text)
            assert USERNAME in who.content[0].text


if __name__ == '__main__':
    base = (sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:1338').rstrip('/')
    asyncio.run(call_mcp(base, get_token(base)))
    print('E2E OK')
```

- [ ] **Step 2: Run it against the local stack**

Run:
```bash
docker compose exec -T web python manage.py seed_golden
mcp_server/.venv/bin/python tests/oauth_e2e.py http://localhost:1338
```
Expected: prints the DCR client id, login, consent, token, the tool list (12 names), `whoami: {... "username": "alice" ...}` and `E2E OK`.

- [ ] **Step 3: Document remote use**

Append to `mcp_server/README.md`:

```markdown
## Remote use (mobile / any remote MCP client)

The same tools are served remotely at `https://data.etipitaka.com/mcp` over
Streamable HTTP, protected by OAuth 2.1 (dynamic client registration + PKCE):

1. In the client, add a remote MCP connector with URL
   `https://data.etipitaka.com/mcp`.
2. The client discovers the authorization server automatically
   (`/.well-known/oauth-protected-resource/mcp` →
   `/.well-known/oauth-authorization-server`), registers itself, and opens the
   login page — sign in with your E-Tipitaka account and press **Allow**.
3. Done: personal-data tools run as you; canon tools are public.

Tokens last 1 h and refresh automatically for 30 days. Revoke at any time via
the client (it calls `/o/revoke_token/`). No local install or token file is
needed for remote use — those apply only to the local stdio server above.

Operators: the `mcp` compose service runs the remote server; nginx routes
`/mcp` and the protected-resource metadata to it. `OAUTH_ISSUER_URL`
(Django) and `ETIPITAKA_ISSUER_URL` / `ETIPITAKA_RESOURCE_URL` (mcp service)
must name the public site. `tests/oauth_e2e.py` exercises the full flow
against a running stack.
```

- [ ] **Step 4: Run everything once more**

Run:
```bash
docker compose exec -T web python -m pytest -q
mcp_server/.venv/bin/python -m pytest mcp_server -q
docker compose exec -T web python manage.py seed_golden && tests/golden/.venv/bin/python -m pytest tests/golden --base-url http://localhost:1338 -q
```
Expected: Django all green with ≥ 90 % coverage; MCP all green; golden `45 passed`.

- [ ] **Step 5: Commit**

```bash
git add tests/oauth_e2e.py mcp_server/README.md
git commit -m "docs(mcp): remote OAuth usage + end-to-end flow script"
```

---

## After the plan

- Ship via the usual path: merge to `master`, push, `workflow_dispatch` deploy
  (CI builds the `mcp` image and runs DOT migrations through `deploy.sh`).
- Acceptance: add `https://data.etipitaka.com/mcp` in a real mobile client,
  complete login + consent, run `whoami` and `list_bookmarks`.
- Hardening follow-ups recorded in the spec: resource/audience-bound tokens,
  CORS for browser clients, rate limiting on `/o/register/` and `/mcp`.
