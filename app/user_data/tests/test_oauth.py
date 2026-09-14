# -*- coding: utf-8 -*-
"""OAuth 2.1 Authorization Server (django-oauth-toolkit) + MCP resource support."""
import json

import pytest
from oauth2_provider.models import Application

from .conftest import make_oauth_token

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
    body = resp.json()
    assert body['active'] is True
    assert body['username'] == 'alice' and body['user_id'] == alice.pk
    assert body['scopes'] == ['etipitaka:read']
    assert body['client_id'] == tok.application.client_id
    assert isinstance(body['expires_at'], int)


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
