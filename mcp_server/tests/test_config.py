from etipitaka_mcp.config import load_config


def test_defaults(monkeypatch):
    for var in ['ETIPITAKA_BASE_URL', 'ETIPITAKA_USERNAME', 'ETIPITAKA_PASSWORD',
                'ETIPITAKA_TOKEN', 'ETIPITAKA_RESOURCES_DIR', 'ETIPITAKA_DEFAULT_EDITION']:
        monkeypatch.delenv(var, raising=False)
    cfg = load_config()
    assert cfg.base_url == 'https://data.etipitaka.com'
    assert cfg.username is None and cfg.token is None
    assert cfg.resources_dir is None


def test_reads_env(monkeypatch):
    monkeypatch.setenv('ETIPITAKA_BASE_URL', 'http://localhost:1338')
    monkeypatch.setenv('ETIPITAKA_USERNAME', 'alice')
    monkeypatch.setenv('ETIPITAKA_DEFAULT_EDITION', 'thaiwn')
    cfg = load_config()
    assert cfg.base_url == 'http://localhost:1338'
    assert cfg.username == 'alice'
    assert cfg.default_edition == 'thaiwn'
