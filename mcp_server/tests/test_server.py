import sqlite3

import pytest


@pytest.fixture
def server(tmp_path, monkeypatch):
    # canon fixture
    conn = sqlite3.connect(str(tmp_path / 'thai.sqlite'))
    conn.execute('CREATE TABLE main (volume VARCHAR(2), page VARCHAR(4), '
                 'items VARCHAR(100), content TEXT)')
    conn.execute("INSERT INTO main VALUES ('10','0101','1','ธรรมอันเลิศ')")
    conn.commit()
    conn.close()
    monkeypatch.setenv('ETIPITAKA_RESOURCES_DIR', str(tmp_path))
    monkeypatch.setenv('ETIPITAKA_DEFAULT_EDITION', 'thai')
    monkeypatch.setenv('ETIPITAKA_TOKEN', 'TOK')
    import importlib
    import etipitaka_mcp.server as srv
    return importlib.reload(srv)


def test_search_canon_uses_default_edition(server):
    out = server._search_canon('ธรรมอันเลิศ')
    assert out['count'] == 1 and out['items'][0]['page'] == '0101'


def test_get_passage(server):
    assert server._get_passage('thai', 10, 101)['content'] == 'ธรรมอันเลิศ'


def test_resolve_reference_ios(server):
    # ios code 1 -> 'thai'
    assert server._resolve_reference('ios', 1, 10, 101)['content'] == 'ธรรมอันเลิศ'


def test_list_editions_marks_present(server):
    eds = {e['key']: e for e in server._list_editions()['editions']}
    assert eds['thai']['present'] is True
    assert eds['thaiwn']['present'] is False


def test_canon_requires_resources_dir(tmp_path, monkeypatch):
    monkeypatch.delenv('ETIPITAKA_RESOURCES_DIR', raising=False)
    monkeypatch.setenv('ETIPITAKA_TOKEN', 'TOK')
    import importlib
    import etipitaka_mcp.server as srv
    srv = importlib.reload(srv)
    with pytest.raises(ValueError):
        srv._search_canon('x')
