import pytest

from etipitaka_mcp.config import Config, load_config

ALL_VARS = ['ETIPITAKA_BASE_URL', 'ETIPITAKA_USERNAME', 'ETIPITAKA_PASSWORD',
            'ETIPITAKA_TOKEN', 'ETIPITAKA_DEFAULT_EDITION', 'ETIPITAKA_TRANSPORT',
            'ETIPITAKA_ISSUER_URL', 'ETIPITAKA_RESOURCE_URL', 'ETIPITAKA_HTTP_HOST',
            'ETIPITAKA_HTTP_PORT', 'ETIPITAKA_ALLOWED_HOSTS', 'ETIPITAKA_ALLOWED_ORIGINS']


def test_defaults(monkeypatch):
    for var in ALL_VARS:
        monkeypatch.delenv(var, raising=False)
    cfg = load_config()
    assert cfg.base_url == 'https://data.etipitaka.com'
    assert cfg.username is None and cfg.token is None
    assert cfg.default_edition is None
    assert cfg.transport == 'stdio'
    assert cfg.issuer_url is None and cfg.resource_url is None
    assert cfg.http_host == '0.0.0.0' and cfg.http_port == 8001
    assert cfg.allowed_hosts == ['localhost:*', '127.0.0.1:*', '[::1]:*']
    assert cfg.allowed_origins == []


def test_reads_env(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_BASE_URL', 'http://localhost:1338')
    monkeypatch.setenv('ETIPITAKA_USERNAME', 'alice')
    monkeypatch.setenv('ETIPITAKA_DEFAULT_EDITION', 'thai')
    monkeypatch.setenv('ETIPITAKA_TRANSPORT', 'http')
    monkeypatch.setenv('ETIPITAKA_ISSUER_URL', 'https://as.example')
    monkeypatch.setenv('ETIPITAKA_RESOURCE_URL', 'https://rs.example/mcp')
    monkeypatch.setenv('ETIPITAKA_HTTP_HOST', '127.0.0.1')
    monkeypatch.setenv('ETIPITAKA_HTTP_PORT', '9000')
    monkeypatch.setenv('ETIPITAKA_ALLOWED_HOSTS', 'rs.example, localhost:*')
    monkeypatch.setenv('ETIPITAKA_ALLOWED_ORIGINS', 'https://app.example, https://other.example')
    cfg = load_config()
    assert cfg.base_url == 'http://localhost:1338'
    assert cfg.username == 'alice'
    assert cfg.default_edition == 'thai'
    assert cfg.transport == 'http'
    assert cfg.issuer_url == 'https://as.example'
    assert cfg.resource_url == 'https://rs.example/mcp'
    assert cfg.http_host == '127.0.0.1'
    assert cfg.http_port == 9000
    assert cfg.allowed_hosts == ['rs.example', 'localhost:*']
    assert cfg.allowed_origins == ['https://app.example', 'https://other.example']


def test_unknown_transport_raises(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_TRANSPORT', 'websocket')
    with pytest.raises(ValueError, match='ETIPITAKA_TRANSPORT'):
        load_config()


def test_transport_is_normalised(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_TRANSPORT', 'HTTP ')
    cfg = load_config()
    assert cfg.transport == 'http'


def test_non_numeric_port_raises(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_HTTP_PORT', 'not-a-number')
    with pytest.raises(ValueError, match='ETIPITAKA_HTTP_PORT'):
        load_config()


def test_urls_trailing_slash_stripped(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_ISSUER_URL', 'https://as.example/')
    monkeypatch.setenv('ETIPITAKA_RESOURCE_URL', 'https://rs.example/mcp/')
    cfg = load_config()
    assert cfg.issuer_url == 'https://as.example'
    assert cfg.resource_url == 'https://rs.example/mcp'


def test_urls_unset_stay_none(monkeypatch):
    monkeypatch.delenv('ETIPITAKA_ISSUER_URL', raising=False)
    monkeypatch.delenv('ETIPITAKA_RESOURCE_URL', raising=False)
    cfg = load_config()
    assert cfg.issuer_url is None
    assert cfg.resource_url is None


def test_direct_construction_matches_load_config_default(monkeypatch):
    for var in ALL_VARS:
        monkeypatch.delenv(var, raising=False)
    direct = Config(base_url='https://data.etipitaka.com', username=None,
                     password=None, token=None, default_edition=None)
    loaded = load_config()
    assert direct.allowed_hosts == loaded.allowed_hosts

    direct.allowed_hosts.append('mutated:*')
    other = Config(base_url='https://data.etipitaka.com', username=None,
                    password=None, token=None, default_edition=None)
    assert other.allowed_hosts != direct.allowed_hosts
    assert 'mutated:*' not in other.allowed_hosts
