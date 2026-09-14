# -*- coding: utf-8 -*-
"""OAuth 2.1 Authorization Server (django-oauth-toolkit) + MCP resource support."""
import json

import pytest
from oauth2_provider.models import Application

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
