import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from user_data.models import UserData, SyncData, Sharing
from user_data.tests.conftest import make_syncdata, make_userdata

pytestmark = pytest.mark.django_db


# --- authentication gate ---

def test_sync_data_list_requires_auth(api):
    assert api.get('/sync_data_list/').status_code in (401, 403)


def test_sync_data_list_authed(auth_alice, alice):
    make_syncdata(alice)
    resp = auth_alice.get('/sync_data_list/')
    assert resp.status_code == 200
    assert 'items' in resp.json()


# --- user / user_list / sharing_list ---

def test_user_returns_target_syncdata(auth_alice, alice, bob):
    make_syncdata(bob)
    resp = auth_alice.get('/user/%d/' % bob.pk)
    assert resp.status_code == 200
    assert 'items' in resp.json()


def test_user_list_returns_followed_owners(auth_alice, alice, bob):
    Sharing.objects.create(owner=bob, follower=alice)
    resp = auth_alice.get('/user_list/')
    assert resp.status_code == 200
    items = resp.json()['items']
    assert any(i['pk'] == bob.pk for i in items)


def test_sharing_list_excludes_self(auth_alice, alice, bob):
    resp = auth_alice.get('/sharing_list/')
    assert resp.status_code == 200
    items = resp.json()['items']
    assert all(i['pk'] != alice.pk for i in items)
    assert any(i['pk'] == bob.pk for i in items)


# --- follower add / remove ---

def test_follower_add(auth_alice, alice, bob):
    resp = auth_alice.post('/follower/%d/' % bob.pk)
    assert resp.status_code == 200
    assert Sharing.objects.filter(owner=alice, follower=bob).count() == 1


def test_follower_add_is_idempotent(auth_alice, alice, bob):
    Sharing.objects.create(owner=alice, follower=bob)
    resp = auth_alice.post('/follower/%d/' % bob.pk)
    assert resp.status_code == 404  # POST when already following -> Http404


def test_follower_remove(auth_alice, alice, bob):
    Sharing.objects.create(owner=alice, follower=bob)
    resp = auth_alice.delete('/follower/%d/' % bob.pk)
    assert resp.status_code == 200
    assert Sharing.objects.filter(owner=alice, follower=bob).count() == 0


# --- download_user_data: sharing access control ---

def test_download_user_data_denied_without_sharing(auth_alice, alice, bob):
    make_syncdata(bob, name='b.json')
    resp = auth_alice.get('/user/%d/b.json/' % bob.pk)
    assert resp.status_code == 404


def test_download_user_data_allowed_with_sharing(auth_alice, alice, bob, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    Sharing.objects.create(owner=bob, follower=alice)
    sd = make_syncdata(bob, name='b.json')
    _write_media(settings.MEDIA_ROOT, sd.file.name, b'{}')
    resp = auth_alice.get('/user/%d/b.json/' % bob.pk)
    assert resp.status_code == 200


# --- download_sync_data ---

def test_download_sync_data_404(auth_alice, alice):
    resp = auth_alice.get('/sync_data/missing.json/')
    assert resp.status_code == 404


def test_download_sync_data_ok(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    sd = make_syncdata(alice, name='s.json')
    _write_media(settings.MEDIA_ROOT, sd.file.name, b'{}')
    resp = auth_alice.get('/sync_data/s.json/')
    assert resp.status_code == 200
    assert resp['Content-Type'] == 'application/etipitaka'


# --- upload_sync_data ---

def test_upload_sync_data_creates_row_and_checksum(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    upload = SimpleUploadedFile('s.json', b'{"v":1}', content_type='application/json')
    resp = auth_alice.post('/sync_data/', {
        'platform': 'ios', 'timestamp': '2020-01-01T00:00:00+00:00', 'file': upload,
    }, format='multipart')
    assert resp.status_code == 200
    body = resp.json()
    assert body['success'] is True
    row = SyncData.objects.get(user=alice, name='s.json')
    assert row.checksum  # md5 was computed


def test_upload_sync_data_no_file_returns_failure(auth_alice, alice):
    resp = auth_alice.post('/sync_data/', {'timestamp': '2020-01-01T00:00:00+00:00'})
    assert resp.status_code == 200
    assert resp.json()['success'] is False


# --- upload_view ---

def test_upload_view_creates_userdata(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    upload = SimpleUploadedFile('d.json', b'{"v":1}', content_type='application/json')
    resp = auth_alice.post('/upload/', {'title': 't', 'file': upload}, format='multipart')
    assert resp.status_code == 200
    assert resp.json()['success'] is True
    assert UserData.objects.filter(user=alice).count() == 1


def test_upload_view_detects_existing_file(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    make_userdata(alice, name='d.json')  # path alice/ios/d.json already present
    upload = SimpleUploadedFile('d.json', b'{"v":1}', content_type='application/json')
    resp = auth_alice.post('/upload/', {'title': 't', 'file': upload}, format='multipart')
    assert resp.status_code == 200
    assert resp.json().get('file_exists') is True


# --- user_data_action: GET / DELETE / soft-delete ---

def test_user_data_action_get_ok(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    ud = make_userdata(alice, name='d.json')
    _write_media(settings.MEDIA_ROOT, ud.file.name, b'{}')
    resp = auth_alice.get('/user_data/%d/' % ud.pk)
    assert resp.status_code == 200


def test_user_data_action_get_deleted_is_404(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    ud = make_userdata(alice, deleted=True, name='d.json')
    _write_media(settings.MEDIA_ROOT, ud.file.name, b'{}')
    resp = auth_alice.get('/user_data/%d/' % ud.pk)
    assert resp.status_code == 404


def test_user_data_action_delete_soft_deletes(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    ud = make_userdata(alice, name='d.json')
    _write_media(settings.MEDIA_ROOT, ud.file.name, b'{}')
    resp = auth_alice.delete('/user_data/%d/' % ud.pk)
    assert resp.status_code == 200
    ud.refresh_from_db()
    assert ud.deleted is True


# --- user_data_list ---

def test_user_data_list_excludes_deleted_by_default(auth_alice, alice):
    make_userdata(alice, deleted=False, name='live.json')
    make_userdata(alice, deleted=True, name='gone.json')
    resp = auth_alice.get('/user_data_list/')
    assert resp.status_code == 200
    assert 'live.json' in resp.json()['items']
    assert 'gone.json' not in resp.json()['items']


def test_user_data_list_deleted_flag(auth_alice, alice):
    make_userdata(alice, deleted=True, name='gone.json')
    resp = auth_alice.get('/user_data_list/?deleted=1')
    assert resp.status_code == 200
    assert 'gone.json' in resp.json()['items']


# --- user_data_view / index_view / login_view ---

def test_user_data_view_redirects_anon(api):
    resp = api.get('/user_data/')
    assert resp.status_code == 302


def test_index_view_anonymous_renders(api):
    resp = api.get('/')
    assert resp.status_code == 200


def test_index_view_authenticated_redirects(auth_alice):
    resp = auth_alice.get('/')
    assert resp.status_code == 302
    assert resp['Location'] == '/user_data/'


def test_login_view_get(api):
    assert api.get('/login/').status_code == 200


def test_login_view_post_valid(api, alice):
    resp = api.post('/login/', {'username': 'alice', 'password': 'alicepass123'})
    assert resp.status_code == 302


def test_login_view_post_invalid(api, alice):
    resp = api.post('/login/', {'username': 'alice', 'password': 'wrong'})
    assert resp.status_code == 200


def _write_media(media_root, rel_name, content):
    import os
    dest = os.path.join(media_root, rel_name)
    parent = os.path.dirname(dest)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    with open(dest, 'wb') as handle:
        handle.write(content)
