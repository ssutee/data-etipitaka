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


TAG_SCHEMA = ("CREATE TABLE tag (name TEXT, history TEXT, note TEXT, "
              "highlight TEXT, priority INTEGER, code INTEGER)")
HISTORY_SCHEMA = ("CREATE TABLE history (keywords TEXT, created FLOAT, detail TEXT, "
                  "code INTEGER, starred INTEGER, state INTEGER, read TEXT, "
                  "skimmed TEXT, items TEXT, marked TEXT, type INTEGER, note TEXT, "
                  "buddhawaj BOOLEAN, note_items TEXT, note_state INTEGER, priority INTEGER)")
LEXICON_SCHEMA = "CREATE TABLE lexicon (type INTEGER, head TEXT, translation TEXT)"


def test_tags_name_search(media_tmp, auth_alice, alice):
    make_content_db(alice, 'tag.sqlite', 'tag', TAG_SCHEMA,
                    [('ขันธ์', '', '', '', 0, 1), ('ธาตุ', '', '', '', 0, 1)])
    assert auth_alice.get('/api/content/tags/?q=ขันธ์').json()['count'] == 1
    assert auth_alice.get('/api/content/tags/').json()['count'] == 2


def test_history_starred_filter(media_tmp, auth_alice, alice):
    row = ('อานาปานสติ', 0.0, '', 1, 1, 0, '', '', '', '', 1, '', 1, '', 0, 0)
    row2 = ('เวทนา', 0.0, '', 1, 0, 0, '', '', '', '', 1, '', 1, '', 0, 0)
    make_content_db(alice, 'history.sqlite', 'history', HISTORY_SCHEMA, [row, row2])
    assert auth_alice.get('/api/content/history/?starred=1').json()['count'] == 1
    assert auth_alice.get('/api/content/history/?q=อานา').json()['count'] == 1


def test_lexicon_head_search(media_tmp, auth_alice, alice):
    make_content_db(alice, 'saved_lexicon.sqlite', 'lexicon', LEXICON_SCHEMA,
                    [(1, 'ภว', 'ความมี, ความเป็น')])
    body = auth_alice.get('/api/content/lexicon/?q=ภว').json()
    assert body['count'] == 1 and body['items'][0]['translation'].startswith('ความ')


def test_summary_counts_per_type_and_platform(media_tmp, auth_alice, alice):
    make_content_db(alice, 'bookmark.sqlite', 'bookmark', BOOKMARK_SCHEMA,
                    [(0, 1, 'a', 0, 1, 1, 1)], platform='ios')
    make_content_db(alice, 'tag.sqlite', 'tag', TAG_SCHEMA,
                    [('ขันธ์', '', '', '', 0, 1)], platform='ios')
    body = auth_alice.get('/api/content/summary/').json()
    assert body['username'] == 'alice'
    assert body['platforms'] == ['ios']
    assert body['counts']['bookmarks'] == {'ios': 1}
    assert body['counts']['tags'] == {'ios': 1}
    assert body['counts']['highlights'] == {}
