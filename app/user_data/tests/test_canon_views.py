# -*- coding: utf-8 -*-
"""Endpoint tests for the public /api/canon/* API (no auth required)."""
from user_data import canon_registry as reg
from .conftest import make_canon_edition, make_canon_dict

EDITION_ROWS = [
    ('01', '0001', 'items-a', 'alpha teaching'),
    ('01', '0002', 'items-b', 'beta content'),
    ('02', '0001', 'items-c', 'alpha again'),
]
DICT_COLS = reg.DICTIONARIES['pali_thai']['columns']
DICT_ROWS = [('buddha', 'ผู้รู้', 'n', '', '', '', '', '', '', 'buddha', 'awakened', 's')]


def test_editions_public_no_auth(api, canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    resp = api.get('/api/canon/editions/')
    assert resp.status_code == 200
    body = resp.json()
    present = {e['key']: e['present'] for e in body['editions']}
    assert present['thai'] is True and present['palinew'] is False
    assert any(d['key'] == 'pali_thai' for d in body['dictionaries'])


def test_search_ok(api, canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    resp = api.get('/api/canon/search/', {'edition': 'thai', 'query': 'alpha'})
    assert resp.status_code == 200
    body = resp.json()
    assert body['count'] == 2 and body['limit'] == 20 and body['offset'] == 0
    assert body['items'][0]['edition'] == 'thai'


def test_search_volume_and_paging(api, canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    resp = api.get('/api/canon/search/',
                   {'edition': 'thai', 'query': 'alpha', 'volume': '1', 'limit': '1'})
    body = resp.json()
    assert body['count'] == 1 and body['limit'] == 1
    assert body['items'][0]['volume'] == '01'


def test_search_unknown_edition_400(api, canon_dir):
    resp = api.get('/api/canon/search/', {'edition': 'nope', 'query': 'x'})
    assert resp.status_code == 400


def test_search_missing_query_400(api, canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    resp = api.get('/api/canon/search/', {'edition': 'thai'})
    assert resp.status_code == 400


def test_search_edition_not_provisioned_503(api, canon_dir):
    resp = api.get('/api/canon/search/', {'edition': 'thai', 'query': 'x'})
    assert resp.status_code == 503


def test_passage_ok_and_not_found(api, canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    ok = api.get('/api/canon/passage/', {'edition': 'thai', 'volume': '1', 'page': '1'})
    assert ok.status_code == 200 and ok.json()['content'] == 'alpha teaching'
    miss = api.get('/api/canon/passage/', {'edition': 'thai', 'volume': '9', 'page': '9'})
    assert miss.status_code == 404


def test_passage_missing_params_400(api, canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    resp = api.get('/api/canon/passage/', {'edition': 'thai', 'volume': '1'})
    assert resp.status_code == 400


def test_resolve_ios_code(api, canon_dir):
    make_canon_edition(canon_dir, 'thai.sqlite', EDITION_ROWS)
    resp = api.get('/api/canon/resolve/',
                   {'platform': 'ios', 'code': '1', 'volume': '1', 'page': '1'})
    assert resp.status_code == 200 and resp.json()['edition'] == 'thai'


def test_resolve_bad_code_400(api, canon_dir):
    resp = api.get('/api/canon/resolve/',
                   {'platform': 'ios', 'code': '999', 'volume': '1', 'page': '1'})
    assert resp.status_code == 400


def test_dictionary_lookup(api, canon_dir):
    make_canon_dict(canon_dir, 'p2t_dict.sqlite', 'p2t', DICT_COLS, DICT_ROWS)
    resp = api.get('/api/canon/dictionary/', {'term': 'buddha'})
    assert resp.status_code == 200
    body = resp.json()
    assert body['count'] == 1 and body['entries'][0]['content'] == 'ผู้รู้'


def test_dictionary_unknown_key_400(api, canon_dir):
    resp = api.get('/api/canon/dictionary/', {'term': 'x', 'dictionary': 'klingon'})
    assert resp.status_code == 400


def test_dictionary_bad_match_400(api, canon_dir):
    resp = api.get('/api/canon/dictionary/', {'term': 'x', 'match': 'fuzzy'})
    assert resp.status_code == 400
