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
