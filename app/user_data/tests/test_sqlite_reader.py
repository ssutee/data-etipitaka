import os

import pytest

from user_data.sqlite_reader import read_table
from user_data.tests.conftest import make_content_db

pytestmark = pytest.mark.django_db

BOOKMARK_SCHEMA = ("CREATE TABLE bookmark (created FLOAT, important INTEGER, "
                   "note TEXT, rank INTEGER, code INTEGER, volume INTEGER, page INTEGER)")


def test_reads_rows_and_tags_platform(media_tmp, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(1457843335.09, 1, 'ธรรมอันเลิศ', 0, 1, 10, 101)])
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert total == 1
    assert rows[0]['note'] == 'ธรรมอันเลิศ'
    assert rows[0]['platform'] == 'ios'


def test_normalizes_created_timestamp(media_tmp, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(1457843335.09, 0, '', 0, 1, 10, 101)])
    rows, _ = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert rows[0]['created'].startswith('2016-03-13')


def test_missing_file_and_missing_table_return_empty(media_tmp, alice):
    from user_data.models import SyncData
    sd = SyncData(user=alice, name='bookmark.sqlite', platform='ios')
    sd.file.name = 'alice/ios/bookmark.sqlite'
    sd.save()
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert (rows, total) == ([], 0)

    # missing-table: a real DB file that lacks the requested table
    make_content_db(alice, 'bookmark.sqlite', 'other',
                    'CREATE TABLE other (x INTEGER)', [(1,)])
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert (rows, total) == ([], 0)


def test_filters_search_and_pagination(media_tmp, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA, [
        (0, 1, 'alpha', 0, 1, 10, 1),
        (0, 0, 'beta', 0, 1, 11, 2),
        (0, 1, 'gamma note', 0, 2, 12, 3),
    ])
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark',
                             filters={'code': '1'})
    assert total == 2
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark',
                             search=(['note'], 'note'))
    assert total == 1 and rows[0]['note'] == 'gamma note'
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark',
                             limit=1, offset=1)
    assert total == 3 and len(rows) == 1


def test_own_data_only(media_tmp, alice, bob):
    make_content_db(bob, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 1, 'bobmark', 0, 1, 1, 1)])
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert (rows, total) == ([], 0)


def test_platform_filter(media_tmp, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 0, 'ios-note', 0, 1, 1, 1)], platform='ios')
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 0, 'android-note', 0, 1, 1, 1)], platform='android')
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark', platform='android')
    assert total == 1
    assert rows[0]['note'] == 'android-note' and rows[0]['platform'] == 'android'


def test_aggregates_across_platforms(media_tmp, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 0, 'a', 0, 1, 1, 1)], platform='ios')
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 0, 'b', 0, 1, 1, 1)], platform='android')
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert total == 2
    assert {r['platform'] for r in rows} == {'ios', 'android'}


def test_corrupt_db_skipped(media_tmp, alice):
    from django.conf import settings
    from user_data.models import SyncData
    rel = 'alice/ios/bookmark.sqlite'
    dest = os.path.join(settings.MEDIA_ROOT, rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, 'wb') as f:
        f.write(b'this is not a sqlite database')
    sd = SyncData(user=alice, name='bookmark.sqlite', platform='ios')
    sd.file.name = rel
    sd.save()
    rows, total = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert (rows, total) == ([], 0)


def test_iso_fallback_on_non_numeric_created(media_tmp, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(None, 0, '', 0, 1, 1, 1)])
    rows, _ = read_table(alice, 'bookmark.sqlite', 'bookmark')
    assert rows[0]['created'] is None
