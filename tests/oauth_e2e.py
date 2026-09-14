"""End-to-end check of the remote MCP OAuth flow against a running stack.

Run by hand (needs the golden seed users):
    docker compose exec -T web python manage.py seed_golden
    mcp_server/.venv/bin/python tests/oauth_e2e.py http://localhost:1338

Flow: DCR -> web login -> consent -> code -> token -> MCP initialize +
tools/list + whoami over Streamable HTTP with the bearer token.

Note: /o/register/ is rate-limited (6/min, burst 5); repeated runs within
a minute may fail with 429.
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
