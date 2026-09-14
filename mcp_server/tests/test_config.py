from etipitaka_mcp.config import load_config

ALL_VARS = ['ETIPITAKA_BASE_URL', 'ETIPITAKA_USERNAME', 'ETIPITAKA_PASSWORD',
            'ETIPITAKA_TOKEN', 'ETIPITAKA_DEFAULT_EDITION', 'ETIPITAKA_TRANSPORT',
            'ETIPITAKA_ISSUER_URL', 'ETIPITAKA_RESOURCE_URL', 'ETIPITAKA_HTTP_HOST',
            'ETIPITAKA_HTTP_PORT', 'ETIPITAKA_ALLOWED_HOSTS']


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
    assert cfg.allowed_hosts == ['localhost:*', '127.0.0.1:*']


def test_reads_env(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_BASE_URL', 'http://localhost:1338')
    monkeypatch.setenv('ETIPITAKA_USERNAME', 'alice')
    monkeypatch.setenv('ETIPITAKA_DEFAULT_EDITION', 'thai')
    monkeypatch.setenv('ETIPITAKA_TRANSPORT', 'http')
    monkeypatch.setenv('ETIPITAKA_ISSUER_URL', 'https://as.example')
    monkeypatch.setenv('ETIPITAKA_RESOURCE_URL', 'https://rs.example/mcp')
    monkeypatch.setenv('ETIPITAKA_HTTP_PORT', '9000')
    monkeypatch.setenv('ETIPITAKA_ALLOWED_HOSTS', 'rs.example, localhost:*')
    cfg = load_config()
    assert cfg.base_url == 'http://localhost:1338'
    assert cfg.username == 'alice'
    assert cfg.default_edition == 'thai'
    assert cfg.transport == 'http'
    assert cfg.issuer_url == 'https://as.example'
    assert cfg.resource_url == 'https://rs.example/mcp'
    assert cfg.http_port == 9000
    assert cfg.allowed_hosts == ['rs.example', 'localhost:*']
