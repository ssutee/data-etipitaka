import stat

import pytest

from etipitaka_mcp.auth import Authenticator, AuthError


def test_uses_explicit_token_without_login(tmp_path):
    auth = Authenticator('http://x', token='TOK', cache_path=tmp_path / 't')
    assert auth.token() == 'TOK'


def test_mints_from_credentials(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/rest-auth/login/', json={'key': 'MINTED'})
    auth = Authenticator('http://x', username='alice', password='pw',
                         cache_path=tmp_path / 't')
    assert auth.token() == 'MINTED'


def test_caches_token_0600(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/rest-auth/login/', json={'key': 'MINTED'})
    cache = tmp_path / 'sub' / 't'
    auth = Authenticator('http://x', username='alice', password='pw', cache_path=cache)
    auth.token()
    assert cache.read_text() == 'MINTED'
    assert stat.S_IMODE(cache.stat().st_mode) == 0o600


def test_reuses_cached_token(tmp_path):
    cache = tmp_path / 't'
    cache.write_text('CACHED')
    auth = Authenticator('http://x', username='alice', password='pw', cache_path=cache)
    assert auth.token() == 'CACHED'


def test_refresh_remints(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/rest-auth/login/', json={'key': 'FRESH'})
    cache = tmp_path / 't'
    cache.write_text('STALE')
    auth = Authenticator('http://x', username='alice', password='pw', cache_path=cache)
    assert auth.token(refresh=True) == 'FRESH'
    assert cache.read_text() == 'FRESH'


def test_no_credentials_raises(tmp_path):
    auth = Authenticator('http://x', cache_path=tmp_path / 't')
    with pytest.raises(AuthError):
        auth.token()


def test_login_failure_raises(tmp_path, httpx_mock):
    httpx_mock.add_response(url='http://x/rest-auth/login/', status_code=400,
                            json={'non_field_errors': ['bad']})
    auth = Authenticator('http://x', username='a', password='b', cache_path=tmp_path / 't')
    with pytest.raises(AuthError):
        auth.token()
