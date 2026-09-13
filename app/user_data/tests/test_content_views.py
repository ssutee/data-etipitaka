import pytest

from user_data.tests.conftest import make_content_db

pytestmark = pytest.mark.django_db

BOOKMARK_SCHEMA = ("CREATE TABLE bookmark (created FLOAT, important INTEGER, "
                   "note TEXT, rank INTEGER, code INTEGER, volume INTEGER, page INTEGER)")
HIGHLIGHT_SCHEMA = ("CREATE TABLE highlight (selection TEXT, type INTEGER, note TEXT, "
                    "start INTEGER, end INTEGER, volume INTEGER, page INTEGER, "
                    "code INTEGER, position INTEGER)")


def test_bookmarks_requires_auth(api):
    assert api.get('/api/content/bookmarks/').status_code in (401, 403)


def test_bookmarks_returns_rows(media_tmp, auth_alice, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 1, 'ธรรม', 0, 1, 10, 101)])
    resp = auth_alice.get('/api/content/bookmarks/')
    assert resp.status_code == 200
    body = resp.json()
    assert body['count'] == 1
    assert body['items'][0]['note'] == 'ธรรม'
    assert body['limit'] == 50 and body['offset'] == 0


def test_bookmarks_volume_filter_and_note_search(media_tmp, auth_alice, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA, [
        (0, 1, 'first', 0, 1, 10, 1),
        (0, 0, 'second', 0, 1, 11, 2),
    ])
    assert auth_alice.get('/api/content/bookmarks/?volume=11').json()['count'] == 1
    assert auth_alice.get('/api/content/bookmarks/?q=first').json()['count'] == 1


def test_bookmarks_limit_clamped(media_tmp, auth_alice, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 0, 'x', 0, 1, 1, 1)])
    body = auth_alice.get('/api/content/bookmarks/?limit=9999').json()
    assert body['limit'] == 500


def test_bookmarks_own_data_only(media_tmp, auth_alice, alice, bob):
    make_content_db(bob, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 1, 'bob', 0, 1, 1, 1)])
    assert auth_alice.get('/api/content/bookmarks/').json()['count'] == 0


def test_highlights_search_selection(media_tmp, auth_alice, alice):
    make_content_db(alice, 'highlight.sqlite', 'highlight', HIGHLIGHT_SCHEMA,
                    [('อาสีวิสสูตร', 1, '', 0, 0, 21, 110, 1, 1)])
    body = auth_alice.get('/api/content/highlights/?q=อาสีวิส').json()
    assert body['count'] == 1
    assert body['items'][0]['selection'] == 'อาสีวิสสูตร'


def test_bookmarks_important_zero_filter(media_tmp, auth_alice, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA, [
        (0, 1, 'imp', 0, 1, 1, 1),
        (0, 0, 'not', 0, 1, 2, 2),
    ])
    body = auth_alice.get('/api/content/bookmarks/?important=0').json()
    assert body['count'] == 1
    assert body['items'][0]['note'] == 'not'
