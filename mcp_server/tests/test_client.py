from etipitaka_mcp.auth import Authenticator
from etipitaka_mcp.client import CanonClient, ContentClient


def _auth(tmp_path, token='TOK'):
    return Authenticator('http://x', token=token, cache_path=tmp_path / 't')


def test_get_sends_token_and_drops_none_params(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/api/content/bookmarks/?volume=10',
                            json={'items': [], 'count': 0})
    client = ContentClient(_auth(tmp_path))
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
    assert ContentClient(auth).get_summary() == {'ok': True}


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
