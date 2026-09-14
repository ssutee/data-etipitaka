import pytest

from etipitaka_mcp.auth import Authenticator
from etipitaka_mcp.client import CanonClient, ContentClient, EtipitakaAPIError


def _auth(tmp_path, token='TOK'):
    return Authenticator('http://x', token=token, cache_path=tmp_path / 't')


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
    httpx_mock.add_response(url='http://internal-django:8000/api/content/summary/',
                            status_code=401)
    client = ContentClient('http://internal-django:8000', lambda: 'ACCESS', scheme='Bearer')
    with pytest.raises(EtipitakaAPIError) as exc_info:
        client.get_summary()
    assert httpx_mock.get_requests()[0].headers['Authorization'] == 'Bearer ACCESS'
    msg = str(exc_info.value)
    assert 'refresh' in msg.lower()
    assert 'http://' not in msg
    assert 'internal-django' not in msg


def test_content_client_500_raises_content_api_error_without_url(httpx_mock):
    httpx_mock.add_response(url='http://internal-django:8000/api/content/bookmarks/',
                            status_code=500)
    client = ContentClient('http://internal-django:8000', lambda: 'TOK')
    with pytest.raises(EtipitakaAPIError) as exc_info:
        client.list_bookmarks()
    msg = str(exc_info.value)
    assert '500' in msg
    assert '/api/content/bookmarks/' in msg
    assert 'http://' not in msg
    assert 'internal-django' not in msg


def test_canon_client_503_raises_etipitaka_api_error_without_url(httpx_mock):
    httpx_mock.add_response(status_code=503)
    client = CanonClient('http://internal-django:8000')
    with pytest.raises(EtipitakaAPIError) as exc_info:
        client.passage(edition='thai', volume=1, page=1)
    msg = str(exc_info.value)
    assert '/api/canon/passage/' in msg
    assert 'http://' not in msg
    assert 'internal-django' not in msg


def test_canon_client_no_auth_header_and_drops_none(httpx_mock):
    httpx_mock.add_response(
        url='http://x/api/canon/search/?edition=thai&query=alpha',
        json={'items': [], 'count': 0})
    CanonClient('http://x/').search(edition='thai', query='alpha', volume=None)
    req = httpx_mock.get_requests()[0]
    assert 'Authorization' not in req.headers
    assert b'volume' not in req.url.query


def test_canon_client_paths(httpx_mock):
    for name in ('editions', 'passage', 'resolve', 'dictionary'):
        httpx_mock.add_response(json={'ok': name})  # matched in registration order
    c = CanonClient('http://x')
    assert c.editions() == {'ok': 'editions'}
    assert c.passage(edition='thai', volume=1, page=1) == {'ok': 'passage'}
    assert c.resolve(platform='ios', code=1, volume=1, page=1) == {'ok': 'resolve'}
    assert c.dictionary(term='buddha') == {'ok': 'dictionary'}
    paths = [r.url.path for r in httpx_mock.get_requests()]
    assert paths == ['/api/canon/editions/', '/api/canon/passage/',
                     '/api/canon/resolve/', '/api/canon/dictionary/']
