# -*- coding: utf-8 -*-
"""OAuth 2.1 Authorization Server (django-oauth-toolkit) + MCP resource support."""
import base64
import hashlib
import json
import secrets
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from oauth2_provider.models import AccessToken, Application, get_refresh_token_model
from oauth2_provider.oauth2_validators import OAuth2Validator

from user_data.oauth_validators import EtipitakaOAuth2Validator

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


# --- EtipitakaOAuth2Validator: per-user advisory lock ------------------------

def _get_tokens(client, alice):
    """Run the authorization_code + PKCE flow for real and return
    (client_id, token response body) -- the starting point every
    validator test below needs a live refresh/access token pair for."""
    reg = client.post('/o/register/', data=json.dumps(DCR_BODY),
                      content_type='application/json').json()
    cid = reg['client_id']
    verifier, challenge = _pkce()
    client.force_login(alice)
    allowed = client.post('/o/authorize/', {**_authz_params(cid, challenge), 'allow': 'Authorize'})
    code = parse_qs(urlparse(allowed['Location']).query)['code'][0]
    resp = client.post('/o/token/', {
        'grant_type': 'authorization_code', 'code': code,
        'redirect_uri': 'https://app.example/cb', 'client_id': cid,
        'code_verifier': verifier,
    })
    assert resp.status_code == 200, resp.content
    return cid, resp.json()


def test_refresh_token_grant_takes_the_advisory_lock(client, alice):
    """save_bearer_token's rotation path (validate_refresh_token too, but
    one lock call is enough to prove the SQL is really reaching Postgres
    through the live token endpoint, not just present in a unit test)."""
    cid, body = _get_tokens(client, alice)
    with CaptureQueriesContext(connection) as ctx:
        resp = client.post('/o/token/', {
            'grant_type': 'refresh_token', 'refresh_token': body['refresh_token'],
            'client_id': cid,
        })
    assert resp.status_code == 200, resp.content
    assert any('pg_advisory_xact_lock' in q['sql'] for q in ctx.captured_queries)


def test_revoke_token_takes_the_advisory_lock(client, alice):
    cid, body = _get_tokens(client, alice)
    with CaptureQueriesContext(connection) as ctx:
        resp = client.post('/o/revoke_token/', {
            'token': body['access_token'], 'client_id': cid,
        })
    assert resp.status_code == 200, resp.content
    assert any('pg_advisory_xact_lock' in q['sql'] for q in ctx.captured_queries)
    assert not AccessToken.objects.filter(user=alice).exists()


def test_replaying_a_rotated_refresh_token_revokes_the_family(client, alice):
    """REFRESH_TOKEN_REUSE_PROTECTION, exercised through the live
    validator. This project's REFRESH_TOKEN_GRACE_PERIOD_SECONDS is the
    DOT default, 0, so replaying a refresh token immediately after it was
    rotated away is already reuse (grace_expired is true the instant any
    wall-clock time passes at all) rather than a client retry within a
    grace window -- and reuse must revoke the whole family, killing the
    very access token the legitimate rotation just issued."""
    cid, body1 = _get_tokens(client, alice)
    refresh1 = body1['refresh_token']

    rotated = client.post('/o/token/', {
        'grant_type': 'refresh_token', 'refresh_token': refresh1, 'client_id': cid,
    })
    assert rotated.status_code == 200, rotated.content
    body2 = rotated.json()

    replay = client.post('/o/token/', {
        'grant_type': 'refresh_token', 'refresh_token': refresh1, 'client_id': cid,
    })
    assert replay.status_code == 400, replay.content
    assert replay.json()['error'] == 'invalid_grant'

    check = client.get('/api/oauth/verify/',
                       HTTP_AUTHORIZATION='Bearer ' + body2['access_token'])
    assert check.status_code == 401


def test_refresh_token_deleted_during_rotation_is_invalid_grant(client, alice, monkeypatch):
    """Stands in for a concurrent passkey recovery deleting the refresh
    token row in the gap between validate_refresh_token's lookup and
    save_bearer_token's own re-fetch during rotation (the two are
    separate oauthlib hook calls, not one locked unit -- see
    EtipitakaOAuth2Validator.save_bearer_token's docstring). django-
    oauth-toolkit's own rotation code hits a raw RefreshToken.DoesNotExist
    re-fetching a row that is simply gone; this must surface as a normal
    400 invalid_grant, not an unhandled 500."""
    cid, body = _get_tokens(client, alice)
    real_validate = EtipitakaOAuth2Validator.validate_refresh_token

    def _validate_then_delete(self, refresh_token, oauth_client, request, *args, **kwargs):
        result = real_validate(self, refresh_token, oauth_client, request, *args, **kwargs)
        instance = getattr(request, 'refresh_token_instance', None)
        if instance is not None:
            get_refresh_token_model().objects.filter(pk=instance.pk).delete()
        return result

    monkeypatch.setattr(EtipitakaOAuth2Validator, 'validate_refresh_token', _validate_then_delete)
    resp = client.post('/o/token/', {
        'grant_type': 'refresh_token', 'refresh_token': body['refresh_token'], 'client_id': cid,
    })
    assert resp.status_code == 400, resp.content
    # Not resp.json(): raising from inside save_bearer_token propagates
    # through oauthlib's dispatcher-level exception handling rather than
    # RefreshTokenGrant.create_token_response's own try/except, which is
    # the one that merges in the endpoint's default Content-Type header
    # -- so this response's body is correct JSON, but its Content-Type
    # header is oauthlib/DOT's plain HttpResponse default (text/html),
    # an existing oauthlib quirk this fix does not attempt to paper over.
    assert json.loads(resp.content)['error'] == 'invalid_grant'


def test_save_bearer_token_skips_locking_without_an_authenticated_user():
    """client_credentials (still technically reachable server-side; see
    the OAUTH2_PROVIDER comment in settings.py) and any other grant with
    no resource owner leave request.user unset or an AnonymousUser --
    there is no per-user row to lock, so this must defer straight to the
    base implementation. A live client_credentials round trip needs a
    confidential client and isn't exercised by any other test here, so
    this calls the validator directly instead, with the base
    implementation stubbed out to prove it still runs and no lock is
    attempted (an unpatched call would need a real transaction and a
    fully-formed oauthlib token/request pair neither branch here needs)."""
    validator = EtipitakaOAuth2Validator()
    calls = []

    class _NoUserRequest:
        user = None

    with mock.patch.object(OAuth2Validator, 'save_bearer_token',
                           lambda self, token, request, *a, **kw: calls.append(request)):
        validator.save_bearer_token({'scope': 'x'}, _NoUserRequest())

    assert len(calls) == 1


def test_validate_refresh_token_defers_when_the_token_is_unknown(db):
    """No row for the checksum means nothing to lock against -- this must
    defer straight to the base implementation rather than opening a
    transaction to lock nothing."""
    validator = EtipitakaOAuth2Validator()
    calls = []

    with mock.patch.object(OAuth2Validator, 'validate_refresh_token',
                           lambda self, *a, **kw: calls.append(a) or True):
        result = validator.validate_refresh_token('not-a-real-refresh-token', None, None)

    assert result is True
    assert len(calls) == 1


def test_revoke_token_defers_when_the_request_has_no_client(db):
    """RFC 7009 section 2.1's own bail-out (a request not tied to a
    stored application) means there is no owner to look up at all, let
    alone lock -- must defer straight to the base implementation, which
    is what performs DOT's own identical bail-out."""
    validator = EtipitakaOAuth2Validator()
    calls = []

    class _NoClientRequest:
        client = None

    with mock.patch.object(OAuth2Validator, 'revoke_token',
                           lambda self, *a, **kw: calls.append(a)):
        validator.revoke_token('sometoken', 'access_token', _NoClientRequest())

    assert len(calls) == 1


def test_revoke_token_finds_the_other_token_type_when_the_hint_misses(client, alice):
    """token_type_hint absent defaults the primary lookup to AccessToken;
    revoking the refresh token's own value must still find its owner via
    the fallback lookup over RefreshToken, lock it, and let super()
    revoke it for real (which also revokes its paired access token)."""
    cid, body = _get_tokens(client, alice)
    resp = client.post('/o/revoke_token/', {'token': body['refresh_token'], 'client_id': cid})
    assert resp.status_code == 200, resp.content
    assert not AccessToken.objects.filter(user=alice).exists()


def test_revoke_token_defers_for_a_token_matching_nothing(client, alice):
    """RFC 7009 section 2.2: revoking an unknown token still looks like
    success (200) -- our own lookup finding nothing must defer straight
    to super() for that, not treat it as an error."""
    cid, _body = _get_tokens(client, alice)
    resp = client.post('/o/revoke_token/', {'token': 'not-a-real-token-at-all', 'client_id': cid})
    assert resp.status_code == 200, resp.content


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
