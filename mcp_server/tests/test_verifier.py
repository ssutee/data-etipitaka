import httpx
import pytest

from etipitaka_mcp.verifier import DjangoTokenVerifier

pytestmark = pytest.mark.anyio

VERIFY_URL = 'http://d/api/oauth/verify/'
OK_BODY = {'active': True, 'username': 'alice', 'user_id': 1,
           'scopes': ['etipitaka:read'], 'expires_at': 4102444800,
           'client_id': 'cid-1'}


async def test_valid_token_returns_access_token(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, json=OK_BODY)
    tok = await DjangoTokenVerifier('http://d/').verify_token('abc')
    assert tok is not None
    assert tok.token == 'abc'
    assert tok.scopes == ['etipitaka:read']
    assert tok.client_id == 'cid-1'
    assert tok.expires_at == 4102444800
    req = httpx_mock.get_requests()[0]
    assert req.headers['Authorization'] == 'Bearer abc'


async def test_rejected_token_is_none(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, status_code=401)
    assert await DjangoTokenVerifier('http://d').verify_token('bad') is None


async def test_network_error_is_none(httpx_mock):
    httpx_mock.add_exception(httpx.ConnectError('down'))
    assert await DjangoTokenVerifier('http://d').verify_token('x') is None


async def test_cache_hit_skips_second_request(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, json=OK_BODY)
    v = DjangoTokenVerifier('http://d')
    first = await v.verify_token('abc')
    second = await v.verify_token('abc')
    assert first is second
    assert len(httpx_mock.get_requests()) == 1


async def test_negative_result_not_cached(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, status_code=401)
    httpx_mock.add_response(url=VERIFY_URL, json=OK_BODY)
    v = DjangoTokenVerifier('http://d')
    assert await v.verify_token('abc') is None
    assert (await v.verify_token('abc')) is not None
