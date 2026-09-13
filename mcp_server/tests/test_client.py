from etipitaka_mcp.auth import Authenticator
from etipitaka_mcp.client import ContentClient


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
