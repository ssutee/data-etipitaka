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
    assert first == second
    assert first is not second
    assert len(httpx_mock.get_requests()) == 1


async def test_negative_result_not_cached(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, status_code=401)
    httpx_mock.add_response(url=VERIFY_URL, json=OK_BODY)
    v = DjangoTokenVerifier('http://d')
    assert await v.verify_token('abc') is None
    assert (await v.verify_token('abc')) is not None


async def test_malformed_json_body_is_none(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, content=b'not json',
                             headers={'Content-Type': 'application/json'})
    assert await DjangoTokenVerifier('http://d').verify_token('abc') is None


async def test_bad_field_type_is_none(httpx_mock):
    bad_body = dict(OK_BODY, expires_at='soon')
    httpx_mock.add_response(url=VERIFY_URL, json=bad_body)
    assert await DjangoTokenVerifier('http://d').verify_token('abc') is None


async def test_inactive_body_is_none(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, json={'active': False})
    assert await DjangoTokenVerifier('http://d').verify_token('abc') is None


async def test_server_error_is_none_and_logged(httpx_mock, caplog):
    httpx_mock.add_response(url=VERIFY_URL, status_code=500)
    with caplog.at_level('WARNING'):
        assert await DjangoTokenVerifier('http://d').verify_token('abc') is None
    assert any('500' in rec.message for rec in caplog.records)


async def test_cache_hit_scopes_are_independent_copies(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, json=OK_BODY)
    v = DjangoTokenVerifier('http://d')
    first = await v.verify_token('abc')
    first.scopes.append('mutated:scope')
    second = await v.verify_token('abc')
    assert second.scopes == ['etipitaka:read']


async def test_subject_set_from_user_id(httpx_mock):
    httpx_mock.add_response(url=VERIFY_URL, json=OK_BODY)
    tok = await DjangoTokenVerifier('http://d').verify_token('abc')
    assert tok.subject == '1'


async def test_subject_none_when_user_id_absent(httpx_mock):
    body = {k: v for k, v in OK_BODY.items() if k != 'user_id'}
    httpx_mock.add_response(url=VERIFY_URL, json=body)
    tok = await DjangoTokenVerifier('http://d').verify_token('abc')
    assert tok is not None
    assert tok.subject is None
