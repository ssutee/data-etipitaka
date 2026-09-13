# -*- coding: utf-8 -*-
import pytest

from user_data import canon_reader
from user_data import canon_registry as reg
from .conftest import make_canon_edition, make_canon_dict

EDITION_ROWS = [
    ('01', '0001', 'items-a', 'พระผู้มีพระภาค alpha teaching'),
    ('01', '0002', 'items-b', 'beta content here'),
    ('02', '0001', 'items-c', 'alpha appears again'),
]

DICT_COLS = reg.DICTIONARIES['pali_thai']['columns']
DICT_ROWS = [
    ('buddha', 'ผู้รู้', 'n', '', '', '', '', '', '', 'buddha', 'the awakened', 'src'),
    ('buddhi', 'ปัญญา', 'n', '', '', '', '', '', '', 'buddhi', 'intellect', 'src'),
]


def test_search_matches_across_volumes(canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    items, total = canon_reader.search(str(canon_dir), 'thai', 'alpha')
    assert total == 2
    assert [(i['volume'], i['page']) for i in items] == [('01', '0001'), ('02', '0001')]
    assert 'alpha' in items[0]['snippet']


def test_search_volume_filter(canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    items, total = canon_reader.search(str(canon_dir), 'thai', 'alpha', volume=1)
    assert total == 1
    assert items[0]['volume'] == '01'


def test_search_missing_edition_file_raises(canon_dir):
    with pytest.raises(reg.RegistryError):
        canon_reader.search(str(canon_dir), 'thai', 'alpha')


def test_get_page_padded_lookup(canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    row = canon_reader.get_page(str(canon_dir), 'thai', 1, 1)
    assert row['content'].endswith('alpha teaching')
    assert row['edition'] == 'thai'


def test_get_page_not_found_returns_none(canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    assert canon_reader.get_page(str(canon_dir), 'thai', 9, 9) is None


def test_lookup_exact_prefix_contains(canon_dir):
    make_canon_dict(canon_dir, 'p2t_dict.sqlite', 'p2t', DICT_COLS, DICT_ROWS)
    exact = canon_reader.lookup(str(canon_dir), 'pali_thai', 'buddha', match='exact')
    assert len(exact) == 1 and exact[0]['content'] == 'ผู้รู้'
    prefix = canon_reader.lookup(str(canon_dir), 'pali_thai', 'buddh', match='prefix')
    assert len(prefix) == 2
    contains = canon_reader.lookup(str(canon_dir), 'pali_thai', 'ddhi', match='contains')
    assert len(contains) == 1 and contains[0]['headword'] == 'buddhi'


def test_lookup_bad_match_raises(canon_dir):
    make_canon_dict(canon_dir, 'p2t_dict.sqlite', 'p2t', DICT_COLS, DICT_ROWS)
    with pytest.raises(canon_reader.CanonError):
        canon_reader.lookup(str(canon_dir), 'pali_thai', 'x', match='fuzzy')


def test_lookup_unknown_dictionary_raises(canon_dir):
    with pytest.raises(canon_reader.CanonError):
        canon_reader.lookup(str(canon_dir), 'klingon', 'x')
