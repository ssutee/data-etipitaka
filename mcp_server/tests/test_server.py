import importlib

import pytest


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_BASE_URL', 'http://srv')
    monkeypatch.setenv('ETIPITAKA_DEFAULT_EDITION', 'thai')
    monkeypatch.setenv('ETIPITAKA_TOKEN', 'TOK')
    import etipitaka_mcp.server as srv
    return importlib.reload(srv)


def test_search_canon_uses_default_edition(server, httpx_mock):
    httpx_mock.add_response(json={'items': [{'page': '0101'}], 'count': 1})
    out = server._search_canon('ธรรมอันเลิศ')
    assert out['count'] == 1 and out['items'][0]['page'] == '0101'
    req = httpx_mock.get_requests()[0]
    assert req.url.path == '/api/canon/search/'
    assert b'edition=thai' in req.url.query
    assert 'Authorization' not in req.headers  # canon is public


def test_get_passage(server, httpx_mock):
    httpx_mock.add_response(json={'content': 'ธรรมอันเลิศ'})
    assert server._get_passage('thai', 10, 101)['content'] == 'ธรรมอันเลิศ'
    assert httpx_mock.get_requests()[0].url.path == '/api/canon/passage/'


def test_resolve_reference_ios(server, httpx_mock):
    httpx_mock.add_response(json={'content': 'x', 'edition': 'thai'})
    server._resolve_reference('ios', 1, 10, 101)
    req = httpx_mock.get_requests()[0]
    assert req.url.path == '/api/canon/resolve/'
    assert b'platform=ios' in req.url.query and b'code=1' in req.url.query


def test_list_editions(server, httpx_mock):
    httpx_mock.add_response(json={'editions': [], 'dictionaries': []})
    assert 'editions' in server._list_editions()
    assert httpx_mock.get_requests()[0].url.path == '/api/canon/editions/'


def test_lookup_dictionary(server, httpx_mock):
    httpx_mock.add_response(json={'entries': [], 'count': 0})
    server._lookup_dictionary('buddha')
    req = httpx_mock.get_requests()[0]
    assert req.url.path == '/api/canon/dictionary/'
    assert b'dictionary=pali_thai' in req.url.query


def test_search_requires_edition(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_BASE_URL', 'http://srv')
    monkeypatch.delenv('ETIPITAKA_DEFAULT_EDITION', raising=False)
    monkeypatch.setenv('ETIPITAKA_TOKEN', 'TOK')
    import etipitaka_mcp.server as srv
    srv = importlib.reload(srv)
    with pytest.raises(ValueError):
        srv._search_canon('x')
