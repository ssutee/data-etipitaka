import json

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from user_data.models import UserData, SyncData, Sharing
from user_data.tests.conftest import make_syncdata, make_userdata
from user_data.tests.test_oauth import DCR_BODY, _authz_params, _pkce

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


def test_download_user_data_missing_syncdata_is_404(auth_alice, alice, bob):
    # Sharing is granted, but the owner has no syncdata with that name.
    Sharing.objects.create(owner=bob, follower=alice)
    resp = auth_alice.get('/user/%d/missing.json/' % bob.pk)
    assert resp.status_code == 404


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


def test_upload_sync_data_replaces_existing_file_on_disk(auth_alice, alice, tmp_path, settings):
    # An existing SyncData row with the same name+platform whose file is on
    # disk must have that file removed before the replacement is stored.
    settings.MEDIA_ROOT = str(tmp_path)
    old = make_syncdata(alice, name='s.json', platform='ios')
    _write_media(settings.MEDIA_ROOT, old.file.name, b'OLD')
    upload = SimpleUploadedFile('s.json', b'{"v":2}', content_type='application/json')
    resp = auth_alice.post('/sync_data/', {
        'platform': 'ios', 'timestamp': '2020-01-01T00:00:00+00:00', 'file': upload,
    }, format='multipart')
    assert resp.status_code == 200
    assert resp.json()['success'] is True
    # The old row (and its on-disk file) is gone; a single fresh row remains.
    assert SyncData.objects.filter(user=alice, name='s.json').count() == 1
    assert not SyncData.objects.filter(pk=old.pk).exists()
    new = SyncData.objects.get(user=alice, name='s.json')
    with open(new.file.path, 'rb') as handle:
        assert handle.read() == b'{"v":2}'


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


def test_upload_view_detects_pc_platform(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    upload = SimpleUploadedFile('d.etz', b'zzz', content_type='application/octet-stream')
    resp = auth_alice.post('/upload/', {'title': 't', 'file': upload}, format='multipart')
    assert resp.status_code == 200
    assert resp.json()['success'] is True
    assert UserData.objects.get(user=alice).platform == 'pc'


def test_upload_view_detects_android_platform(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    upload = SimpleUploadedFile('d.js', b'zzz', content_type='application/javascript')
    resp = auth_alice.post('/upload/', {'title': 't', 'file': upload}, format='multipart')
    assert resp.status_code == 200
    assert resp.json()['success'] is True
    assert UserData.objects.get(user=alice).platform == 'android'


def test_upload_view_removes_previously_deleted_file(auth_alice, alice, tmp_path, settings):
    # A soft-deleted UserData row with the same path: its file on disk is
    # removed before the fresh upload is stored.
    settings.MEDIA_ROOT = str(tmp_path)
    old = make_userdata(alice, deleted=True, name='d.json')
    _write_media(settings.MEDIA_ROOT, old.file.name, b'OLD')
    upload = SimpleUploadedFile('d.json', b'{"v":1}', content_type='application/json')
    resp = auth_alice.post('/upload/', {'title': 't', 'file': upload}, format='multipart')
    assert resp.status_code == 200
    assert resp.json()['success'] is True
    # A fresh (non-deleted) row was created alongside the old deleted one.
    assert UserData.objects.filter(user=alice, deleted=False).count() == 1


def test_upload_view_invalid_form_returns_failure(auth_alice, alice):
    # No file field -> UploadFileForm is invalid.
    resp = auth_alice.post('/upload/', {'title': 't'}, format='multipart')
    assert resp.status_code == 200
    assert resp.json()['success'] is False


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


def test_user_data_action_delete_missing_returns_failure(auth_alice, alice):
    resp = auth_alice.delete('/user_data/99999/')
    assert resp.status_code == 200
    assert resp.json()['success'] is False


def test_user_data_action_get_missing_is_404(auth_alice, alice):
    resp = auth_alice.get('/user_data/99999/')
    assert resp.status_code == 404


def test_user_data_action_get_etz_content_type(auth_alice, alice, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    ud = make_userdata(alice, name='d.etz')
    _write_media(settings.MEDIA_ROOT, ud.file.name, b'zzz')
    resp = auth_alice.get('/user_data/%d/' % ud.pk)
    assert resp.status_code == 200
    assert resp['Content-Type'] == 'application/etipitaka'


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


def test_index_view_authenticated_redirects(api, alice):
    # index_view is a plain Django view (session auth), not a DRF @api_view,
    # so it needs a real session login rather than the token-header fixture.
    api.force_login(alice)
    resp = api.get('/')
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


def test_user_data_view_authenticated_renders(api, alice):
    api.force_login(alice)
    resp = api.get('/user_data/')
    assert resp.status_code == 200


def test_login_view_post_disabled_account(api, monkeypatch):
    # The default ModelBackend returns None for inactive users, so the
    # disabled-account branch is only reachable when authenticate() yields an
    # inactive user. Patch authenticate to exercise that branch.
    from django.contrib.auth.models import User
    from user_data import views as views_module
    user = User(username='pending', email='p@example.com', is_active=False)
    user.set_password('pw12345678')
    user.save()
    monkeypatch.setattr(views_module, 'authenticate', lambda **kw: user)
    resp = api.post('/login/', {'username': 'pending', 'password': 'pw12345678'})
    assert resp.status_code == 200
    assert resp.context['disabled_account'] is True


def test_login_view_get_with_email_param(api):
    resp = api.get('/login/?email=confirm')
    assert resp.status_code == 200
    assert resp.context['confirm_email'] is True


# --- login_view: honouring `next` (open-redirect safe) ---

def test_login_view_post_with_safe_next_redirects_there(api, alice):
    next_url = '/o/authorize/?client_id=abc123&response_type=code'
    resp = api.post('/login/', {
        'username': 'alice', 'password': 'alicepass123', 'next': next_url,
    })
    assert resp.status_code == 302
    assert resp['Location'] == next_url


def test_login_view_post_with_external_next_falls_back_to_root(api, alice):
    resp = api.post('/login/', {
        'username': 'alice', 'password': 'alicepass123',
        'next': 'https://evil.example/steal',
    })
    assert resp.status_code == 302
    assert resp['Location'] == '/'


def test_login_view_post_without_next_redirects_root(api, alice):
    resp = api.post('/login/', {'username': 'alice', 'password': 'alicepass123'})
    assert resp.status_code == 302
    assert resp['Location'] == '/'


def test_login_view_invalid_credentials_preserves_next(api, alice):
    resp = api.post('/login/?next=%2Fo%2Fauthorize%2F%3Fclient_id%3Dabc', {
        'username': 'alice', 'password': 'wrong',
    })
    assert resp.status_code == 200
    assert resp.context['invalid_login'] is True
    assert resp.context['next'] == '/o/authorize/?client_id=abc'


def test_login_view_disabled_account_preserves_next(api, monkeypatch):
    from django.contrib.auth.models import User
    from user_data import views as views_module
    user = User(username='pending', email='p@example.com', is_active=False)
    user.set_password('pw12345678')
    user.save()
    monkeypatch.setattr(views_module, 'authenticate', lambda **kw: user)
    resp = api.post('/login/?next=%2Fo%2Fauthorize%2F%3Fclient_id%3Dabc', {
        'username': 'pending', 'password': 'pw12345678',
    })
    assert resp.status_code == 200
    assert resp.context['disabled_account'] is True
    assert resp.context['next'] == '/o/authorize/?client_id=abc'


def test_login_view_get_preserves_next_in_context(api):
    resp = api.get('/login/?next=%2Fo%2Fauthorize%2F%3Fclient_id%3Dabc')
    assert resp.status_code == 200
    assert resp.context['next'] == '/o/authorize/?client_id=abc'


def _login_form_html(resp):
    # base.html's language-switcher form also has a hidden `name="next"`
    # field (unrelated, always present), so scope the check to the actual
    # login form (`id="signup"`) rather than the whole rendered page.
    content = resp.content.decode()
    start = content.index('id="signup"')
    end = content.index('</form>', start)
    return content[start:end]


def test_login_form_renders_hidden_next_field_when_present(api):
    resp = api.get('/login/?next=%2Fo%2Fauthorize%2F%3Fclient_id%3Dabc')
    assert resp.status_code == 200
    form_html = _login_form_html(resp)
    assert 'name="next"' in form_html
    assert '/o/authorize/?client_id=abc' in form_html


def test_login_form_omits_hidden_next_field_when_absent(api):
    resp = api.get('/login/')
    assert resp.status_code == 200
    assert 'name="next"' not in _login_form_html(resp)


def test_anonymous_authorize_then_login_lands_back_on_authorize(client, alice):
    # The ordering the current suite misses: an anonymous GET of /o/authorize/
    # redirects to login carrying the full authorization request in `next`;
    # logging in from there must land back on /o/authorize/, not on /.
    reg = client.post('/o/register/', data=json.dumps(DCR_BODY),
                      content_type='application/json').json()
    cid = reg['client_id']
    _, challenge = _pkce()
    params = _authz_params(cid, challenge)

    anon = client.get('/o/authorize/', params)
    assert anon.status_code == 302
    assert anon['Location'].startswith('/login/?next=')

    login_page = client.get(anon['Location'])
    assert login_page.status_code == 200
    next_value = login_page.context['next']
    assert next_value.startswith('/o/authorize/')

    logged_in = client.post('/login/', {
        'username': 'alice', 'password': 'alicepass123', 'next': next_value,
    })
    assert logged_in.status_code == 302
    assert logged_in['Location'].startswith('/o/authorize/')
    assert logged_in['Location'] != '/'


def _write_media(media_root, rel_name, content):
    import os
    dest = os.path.join(media_root, rel_name)
    parent = os.path.dirname(dest)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    with open(dest, 'wb') as handle:
        handle.write(content)
