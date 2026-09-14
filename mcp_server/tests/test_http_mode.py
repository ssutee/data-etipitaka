import importlib
import inspect
import re
from urllib.parse import urlparse

import pytest
from starlette.testclient import TestClient

from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

pytestmark = pytest.mark.anyio

HTTP_ENV = {
    'ETIPITAKA_TRANSPORT': 'http',
    'ETIPITAKA_BASE_URL': 'http://django.test',
    'ETIPITAKA_ISSUER_URL': 'https://as.example',
    'ETIPITAKA_RESOURCE_URL': 'https://rs.example/mcp',
    'ETIPITAKA_ALLOWED_HOSTS': 'testserver,testserver:*',
}

# The twelve @mcp.tool() names registered in server.py.
TOOL_NAMES = [
    'list_bookmarks', 'list_highlights', 'list_tags', 'list_history',
    'list_lexicon', 'get_summary', 'whoami', 'list_editions',
    'search_canon', 'get_passage', 'resolve_reference', 'lookup_dictionary',
]


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


async def test_all_tools_are_coroutine_functions(http_server):
    """FastMCP invokes a sync tool body inline on the request's own task
    (`fn(**args)`, no thread hand-off) — so every registered tool must be
    `async def`, or one caller's blocking REST call stalls every other
    session sharing the worker. Reached via the FastMCP instance's own
    ToolManager.get_tool(name).fn, which is the exact callable dispatched
    for a tool call (verified empirically: `@mcp.tool()` returns the
    original function unchanged, and that same object is what
    ToolManager.get_tool(name).fn holds)."""
    for name in TOOL_NAMES:
        tool = http_server.mcp._tool_manager.get_tool(name)
        assert tool is not None, name
        assert inspect.iscoroutinefunction(tool.fn), name


async def test_off_loop_propagates_request_token_across_thread(http_server):
    """Security-critical: the per-request bearer token must still resolve
    inside the worker thread anyio.to_thread.run_sync hands the blocking
    call to. A bare ThreadPoolExecutor/loop.run_in_executor would not copy
    the contextvar and would silently break per-caller token isolation."""
    token = AccessToken(token='tok-secret', client_id='cid',
                        scopes=['etipitaka:read'])
    user = AuthenticatedUser(token)
    reset = auth_context_var.set(user)
    try:
        result = await http_server._off_loop(http_server._request_token)
    finally:
        auth_context_var.reset(reset)
    assert result == 'tok-secret'

    # Existing behaviour must still hold with no auth context set.
    with pytest.raises(ValueError):
        http_server._request_token()
