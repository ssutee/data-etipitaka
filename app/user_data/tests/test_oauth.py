# -*- coding: utf-8 -*-
"""OAuth 2.1 Authorization Server (django-oauth-toolkit) + MCP resource support."""
import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from oauth2_provider.models import Application

from .conftest import make_content_db, make_oauth_token

pytestmark = pytest.mark.django_db

DCR_BODY = {
    'client_name': 'test-client',
    'redirect_uris': ['https://app.example/cb'],
    'grant_types': ['authorization_code', 'refresh_token'],
    'response_types': ['code'],
    'token_endpoint_auth_method': 'none',
}


def test_dcr_registers_public_client(client):
    resp = client.post('/o/register/', data=json.dumps(DCR_BODY),
                       content_type='application/json')
    assert resp.status_code == 201, resp.content
    body = resp.json()
    assert body['client_id']
    app = Application.objects.get(client_id=body['client_id'])
    assert app.client_type == Application.CLIENT_PUBLIC


def test_as_metadata(client, settings):
    # Override DOT's issuer knob (pytest-django's setting_changed makes DOT
    # reload oauth2_settings); the document must anchor on it, not the request.
    settings.OAUTH2_PROVIDER = {**settings.OAUTH2_PROVIDER,
                                'OIDC_ISS_ENDPOINT': 'https://issuer.example'}
    resp = client.get('/.well-known/oauth-authorization-server')
    assert resp.status_code == 200
    assert resp['Content-Type'].startswith('application/json')
    body = resp.json()
    assert body['issuer'] == 'https://issuer.example'
    assert body['authorization_endpoint'] == 'https://issuer.example/o/authorize/'
    assert body['token_endpoint'] == 'https://issuer.example/o/token/'
    assert body['registration_endpoint'] == 'https://issuer.example/o/register/'
    assert body['revocation_endpoint'] == 'https://issuer.example/o/revoke_token/'
    assert body['scopes_supported'] == ['etipitaka:read']
    assert body['response_types_supported'] == ['code']
    assert body['grant_types_supported'] == ['authorization_code', 'refresh_token']
    assert body['code_challenge_methods_supported'] == ['S256']
    assert body['authorization_response_iss_parameter_supported'] is True
    for key in ('token_endpoint_auth_methods_supported',
                'revocation_endpoint_auth_methods_supported'):
        assert 'none' in body[key] and 'client_secret_basic' in body[key]


def test_verify_valid_token(api, alice):
    tok = make_oauth_token(alice)
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    resp = api.get('/api/oauth/verify/')
    assert resp.status_code == 200
    assert resp['Cache-Control'] == 'no-store'
    body = resp.json()
    assert body['active'] is True
    assert body['username'] == alice.username and body['user_id'] == alice.pk
    assert body['scopes'] == ['etipitaka:read']
    assert body['client_id'] == tok.application.client_id
    assert body['expires_at'] == int(tok.expires.timestamp())


def test_verify_bogus_token_401(api):
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


def test_verify_missing_header_401(api):
    assert api.get('/api/oauth/verify/').status_code == 401


def test_verify_inactive_user_401(api, alice):
    tok = make_oauth_token(alice)
    alice.is_active = False
    alice.save(update_fields=['is_active'])
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    resp = api.get('/api/oauth/verify/')
    assert resp.status_code == 401
    assert 'invalid_token' in resp['WWW-Authenticate']


def test_verify_userless_token_401(api, db):
    tok = make_oauth_token(None)  # client-credentials style: no user
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    resp = api.get('/api/oauth/verify/')
    assert resp.status_code == 401
    assert 'invalid_token' in resp['WWW-Authenticate']


def test_verify_token_without_application_reports_empty_client_id(api, alice):
    tok = make_oauth_token(alice)
    tok.application = None
    tok.save(update_fields=['application'])
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    resp = api.get('/api/oauth/verify/')
    assert resp.status_code == 200 and resp.json()['client_id'] == ''


def _pkce():
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


def _authz_params(cid, challenge):
    return {
        'response_type': 'code', 'client_id': cid,
        'redirect_uri': 'https://app.example/cb', 'scope': 'etipitaka:read',
        'state': 'xyz', 'code_challenge': challenge,
        'code_challenge_method': 'S256',
    }


def test_authorization_code_pkce_flow(client, alice, settings):
    reg = client.post('/o/register/', data=json.dumps(DCR_BODY),
                      content_type='application/json').json()
    cid = reg['client_id']
    verifier, challenge = _pkce()
    params = _authz_params(cid, challenge)
    # Anonymous -> redirected to the site login page.
    anon = client.get('/o/authorize/', params)
    assert anon.status_code == 302 and anon['Location'].startswith(settings.LOGIN_URL)

    client.force_login(alice)
    page = client.get('/o/authorize/', params)
    assert page.status_code == 200
    assert b'test-client' in page.content and b'name="allow"' in page.content
    # Our branded consent page (extends the site's base.html), not DOT's stock
    # template, which extends oauth2_provider/base.html instead.
    assert 'base.html' in [t.name for t in page.templates]
    assert b'navbar-brand' in page.content

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


def test_authorization_denied_redirects_with_access_denied(client, alice):
    reg = client.post('/o/register/', data=json.dumps(DCR_BODY),
                      content_type='application/json').json()
    _, challenge = _pkce()
    params = _authz_params(reg['client_id'], challenge)
    client.force_login(alice)
    # Posting without `allow` is what the Deny button does (it has no name).
    denied = client.post('/o/authorize/', params)
    assert denied.status_code == 302
    loc = urlparse(denied['Location'])
    assert loc.netloc == 'app.example'
    qs = parse_qs(loc.query)
    assert qs['error'] == ['access_denied']
    assert qs['state'] == ['xyz']
    assert 'code' not in qs


def test_consent_page_never_interpolates_client_name(client, alice):
    # base.html boots AngularJS with <[ ]> delimiters; a DCR client name must
    # be shown verbatim, never evaluated in the user's session.
    reg = client.post('/o/register/',
                      data=json.dumps({**DCR_BODY, 'client_name': '<[7*7]>'}),
                      content_type='application/json').json()
    _, challenge = _pkce()
    client.force_login(alice)
    page = client.get('/o/authorize/', _authz_params(reg['client_id'], challenge))
    assert page.status_code == 200
    assert b'ng-non-bindable' in page.content
    assert b'&lt;[7*7]&gt;' in page.content and b'<[7*7]>' not in page.content


def test_consent_page_renders_in_thai(client, alice, settings):
    reg = client.post('/o/register/', data=json.dumps(DCR_BODY),
                      content_type='application/json').json()
    _, challenge = _pkce()
    client.force_login(alice)
    client.cookies[settings.LANGUAGE_COOKIE_NAME] = 'th'
    page = client.get('/o/authorize/', _authz_params(reg['client_id'], challenge))
    assert page.status_code == 200
    assert 'ปฏิเสธ'.encode() in page.content          # Deny (template string)
    assert 'ที่คั่นหน้า'.encode() in page.content     # scope description (settings, gettext_lazy)


BOOKMARK_SQL = ("CREATE TABLE bookmark (created FLOAT, important INTEGER, note TEXT, "
                "rank INTEGER, code INTEGER, volume INTEGER, page INTEGER)")


def _seed_bookmarks(alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SQL,
                    [(1457843335.0, 1, 'n', 0, 1, 10, 101)])


def test_content_accepts_oauth_bearer(oauth_alice, alice, media_tmp):
    _seed_bookmarks(alice)
    resp = oauth_alice.get('/api/content/bookmarks/')
    assert resp.status_code == 200 and resp.json()['count'] == 1


def test_content_oauth_without_scope_403(api, alice):
    tok = make_oauth_token(alice, scope='')
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    resp = api.get('/api/content/bookmarks/')
    assert resp.status_code == 403
    assert 'insufficient_scope' in resp['WWW-Authenticate']


def test_content_drf_token_still_works(auth_alice, alice, media_tmp):
    _seed_bookmarks(alice)
    assert auth_alice.get('/api/content/bookmarks/').status_code == 200


def test_content_anonymous_401_with_bearer_challenge(api):
    resp = api.get('/api/content/bookmarks/')
    assert resp.status_code == 401
    assert resp['WWW-Authenticate'].startswith('Bearer')


def test_summary_accepts_oauth_bearer(oauth_alice):
    assert oauth_alice.get('/api/content/summary/').status_code == 200


def test_content_inactive_user_oauth_401(api, alice):
    # Proves the content views use the active-user subclass, not plain
    # OAuth2Authentication.
    tok = make_oauth_token(alice)
    alice.is_active = False
    alice.save(update_fields=['is_active'])
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    resp = api.get('/api/content/bookmarks/')
    assert resp.status_code == 401
    assert 'invalid_token' in resp['WWW-Authenticate']


def test_content_bogus_drf_token_still_401(api):
    # TokenAuthentication still raises behind the OAuth authenticator.
    api.credentials(HTTP_AUTHORIZATION='Token bogus')
    assert api.get('/api/content/bookmarks/').status_code == 401


def test_canon_still_public(api, canon_dir):
    assert api.get('/api/canon/editions/').status_code == 200


def test_user_details_accepts_oauth_bearer(oauth_alice, alice):
    resp = oauth_alice.get('/rest-auth/user/')
    assert resp.status_code == 200
    body = resp.json()
    assert body['username'] == alice.username
    assert body['pk'] == alice.pk
    assert body['email'] == alice.email


def test_user_details_oauth_without_scope_403(api, alice):
    tok = make_oauth_token(alice, scope='')
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    resp = api.get('/rest-auth/user/')
    assert resp.status_code == 403
    assert 'insufficient_scope' in resp['WWW-Authenticate']


def test_user_details_drf_token_still_works(auth_alice, alice):
    resp = auth_alice.get('/rest-auth/user/')
    assert resp.status_code == 200
    assert resp.json()['username'] == alice.username


# RFC 8707: clients such as ChatGPT send `resource=<MCP URL>` when authorizing,
# so the issued token is audience-bound to the MCP endpoint. The MCP service
# forwards that token to these Django endpoints over the internal network,
# where django-oauth-toolkit's default prefix check would compare the audience
# with http://web:8000/... and reject every such token.
MCP_RESOURCE = 'https://data.etipitaka.com/mcp'


def _bearer(api, tok):
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    return api


def test_verify_accepts_token_bound_to_mcp_resource(api, alice):
    tok = make_oauth_token(alice, resource=[MCP_RESOURCE])
    resp = _bearer(api, tok).get('/api/oauth/verify/')
    assert resp.status_code == 200 and resp.json()['username'] == alice.username


def test_content_accepts_token_bound_to_mcp_resource(api, alice, media_tmp):
    _seed_bookmarks(alice)
    tok = make_oauth_token(alice, resource=[MCP_RESOURCE])
    resp = _bearer(api, tok).get('/api/content/bookmarks/')
    assert resp.status_code == 200 and resp.json()['count'] == 1


def test_user_details_accepts_token_bound_to_mcp_resource(api, alice):
    tok = make_oauth_token(alice, resource=[MCP_RESOURCE])
    resp = _bearer(api, tok).get('/rest-auth/user/')
    assert resp.status_code == 200 and resp.json()['username'] == alice.username


def test_mcp_resource_follows_the_issuer(api, alice, settings):
    settings.OAUTH_MCP_RESOURCE_URL = 'http://localhost:1338/mcp'
    tok = make_oauth_token(alice, resource=['http://localhost:1338/mcp'])
    assert _bearer(api, tok).get('/api/oauth/verify/').status_code == 200


def test_verify_rejects_token_bound_to_foreign_resource(api, alice):
    tok = make_oauth_token(alice, resource=['https://other.example/mcp'])
    resp = _bearer(api, tok).get('/api/oauth/verify/')
    assert resp.status_code == 401
    assert 'invalid_token' in resp['WWW-Authenticate']


def test_verify_rejects_lookalike_of_mcp_resource(api, alice):
    for aud in ('https://data.etipitaka.com/mcp-evil',
                'https://data.etipitaka.com.evil.example/mcp',
                'http://data.etipitaka.com/mcp'):
        tok = make_oauth_token(alice, resource=[aud])
        assert _bearer(api, tok).get('/api/oauth/verify/').status_code == 401, aud
