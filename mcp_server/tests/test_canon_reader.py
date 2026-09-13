import sqlite3

import pytest

from etipitaka_mcp import canon_reader
from etipitaka_mcp import canon_registry as reg


@pytest.fixture
def resources(tmp_path):
    conn = sqlite3.connect(str(tmp_path / 'thai.sqlite'))
    conn.execute('CREATE TABLE main (volume VARCHAR(2), page VARCHAR(4), '
                 'items VARCHAR(100), content TEXT)')
    conn.executemany('INSERT INTO main VALUES (?,?,?,?)', [
        ('01', '0001', '1', 'พระวินัยปิฎก มหาวิภังค์'),
        ('10', '0101', '1', 'ธรรมอันเลิศ ย่อมมี'),
        ('10', '0102', '2', 'อีกหน้าหนึ่ง'),
    ])
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(tmp_path / 'p2t_dict.sqlite'))
    conn.execute('CREATE TABLE p2t (headword text, content text, type text, '
                 'gender text, vachana text, viphat text, category text, '
                 'read text, note text, roman text, eng_content text, source text)')
    conn.execute("INSERT INTO p2t VALUES ('ภว','ความมี','','','','','','','','bhava','','')")
    conn.commit()
    conn.close()
    return str(tmp_path)


def test_search_matches_and_snippets(resources):
    items, total = canon_reader.search(resources, 'thai', 'ธรรมอันเลิศ')
    assert total == 1
    assert items[0]['volume'] == '10' and items[0]['page'] == '0101'
    assert 'ธรรมอันเลิศ' in items[0]['snippet']


def test_search_volume_filter_and_pagination(resources):
    _, total = canon_reader.search(resources, 'thai', 'หน้า', volume=10)
    assert total == 1
    items, total = canon_reader.search(resources, 'thai', '', limit=1, offset=1)
    assert total == 3 and len(items) == 1


def test_get_page_pads_volume_and_page(resources):
    row = canon_reader.get_page(resources, 'thai', 10, 101)
    assert row['content'] == 'ธรรมอันเลิศ ย่อมมี'


def test_get_page_missing_returns_none(resources):
    assert canon_reader.get_page(resources, 'thai', 99, 9999) is None


def test_search_missing_edition_raises(resources):
    with pytest.raises(reg.RegistryError):
        canon_reader.search(resources, 'thaiwn', 'x')


def test_lookup_exact_prefix_contains(resources):
    assert canon_reader.lookup(resources, 'pali_thai', 'ภว')[0]['content'] == 'ความมี'
    assert canon_reader.lookup(resources, 'pali_thai', 'ภ', match='prefix')
    assert canon_reader.lookup(resources, 'pali_thai', 'ว', match='contains')
    assert canon_reader.lookup(resources, 'pali_thai', 'zzz') == []
