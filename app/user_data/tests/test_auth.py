import pytest
from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from user_data import auth_views
from user_data.auth_views import LoginRateThrottle, _signer

pytestmark = pytest.mark.django_db


@pytest.fixture
def api():
    return APIClient()


def _register(api, username='newbie', email='n@example.com'):
    return api.post('/rest-auth/registration/', {
        'email': email, 'username': username,
        'password1': 'pw12345678', 'password2': 'pw12345678',
    })


def test_register_creates_inactive_user_and_sends_mail(api):
    resp = _register(api)
    assert resp.status_code == 201
    user = User.objects.get(username='newbie')
    assert user.is_active is False
    assert len(mail.outbox) == 1
    assert 'n@example.com' in mail.outbox[0].to


def test_register_rejects_password_mismatch(api):
    resp = api.post('/rest-auth/registration/', {
        'email': 'n@example.com', 'username': 'newbie',
        'password1': 'pw12345678', 'password2': 'different',
    })
    assert resp.status_code == 400


def test_register_rejects_duplicate_username(api):
    User.objects.create_user('taken', 't@example.com', 'pw12345678')
    resp = _register(api, username='taken', email='other@example.com')
    assert resp.status_code == 400
    assert 'username' in resp.json()


def test_register_rejects_username_differing_only_by_case(api):
    User.objects.create_user('newbie', 'first@example.com', 'pw12345678')
    resp = _register(api, username='Newbie', email='second@example.com')
    assert resp.status_code == 400
    assert 'username' in resp.json()


def test_register_rejects_email_differing_only_by_case(api):
    User.objects.create_user('someone', 'N@x.com', 'pw12345678')
    resp = _register(api, username='newbie', email='n@x.com')
    assert resp.status_code == 400
    assert 'email' in resp.json()


def test_register_rejects_email_too_long(api):
    """User.email is a varchar(254); an over-length address must be a
    clean 400 from serializer validation, not a raw DataError 500 from
    the database when the row is saved."""
    resp = _register(api, email='a' * 250 + '@example.com')
    assert resp.status_code == 400
    assert 'email' in resp.json()


def test_login_returns_token_for_active_user(api):
    user = User.objects.create_user('active', 'a@example.com', 'pw12345678')
    resp = api.post('/rest-auth/login/', {'username': 'active', 'password': 'pw12345678'})
    assert resp.status_code == 200
    assert resp.json()['key'] == Token.objects.get(user=user).key


def test_login_rejected_for_inactive_user(api):
    user = User(username='pending', email='p@example.com', is_active=False)
    user.set_password('pw12345678')
    user.save()
    resp = api.post('/rest-auth/login/', {'username': 'pending', 'password': 'pw12345678'})
    assert resp.status_code == 400


def test_login_rejected_for_bad_password(api):
    User.objects.create_user('active', 'a@example.com', 'pw12345678')
    resp = api.post('/rest-auth/login/', {'username': 'active', 'password': 'wrong'})
    assert resp.status_code == 400


def test_logout_deletes_token(api):
    user = User.objects.create_user('active', 'a@example.com', 'pw12345678')
    token = Token.objects.create(user=user)
    api.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
    resp = api.post('/rest-auth/logout/')
    assert resp.status_code == 200
    assert Token.objects.filter(user=user).count() == 0


def test_user_details(api):
    user = User.objects.create_user('active', 'a@example.com', 'pw12345678')
    token = Token.objects.create(user=user)
    api.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
    resp = api.get('/rest-auth/user/')
    assert resp.status_code == 200
    assert resp.json()['username'] == 'active'


def test_verify_email_activates_account(api):
    user = User(username='pending', email='p@example.com', is_active=False)
    user.set_password('pw12345678')
    user.save()
    token = _signer().sign(str(user.pk))
    resp = api.post('/rest-auth/registration/verify-email/', {'key': token})
    assert resp.status_code == 200
    user.refresh_from_db()
    assert user.is_active is True


def test_verify_email_rejects_bad_token(api):
    resp = api.post('/rest-auth/registration/verify-email/', {'key': 'garbage'})
    assert resp.status_code == 400


def test_verify_email_rejects_token_for_deleted_user(api):
    # A validly-signed token whose user no longer exists must be rejected.
    user = User.objects.create_user('gone', 'gone@example.com', 'pw12345678')
    token = _signer().sign(str(user.pk))
    user.delete()
    resp = api.post('/rest-auth/registration/verify-email/', {'key': token})
    assert resp.status_code == 400


@pytest.mark.parametrize('body', [
    [],
    'x',
    7,
    None,
    {'key': 7},
    {'key': []},
], ids=['list', 'string', 'number', 'null', 'key-is-int', 'key-is-list'])
def test_verify_email_rejects_hostile_body_without_500(api, body):
    # request.data can be any JSON top-level value (a bare list/string/
    # number/null), and even inside a dict 'key' can be any JSON type --
    # none of these may ever reach a 5xx (see _key_from_body's docstring).
    resp = api.post('/rest-auth/registration/verify-email/', body, format='json')
    assert resp.status_code == 400


def test_verify_email_uses_same_throttle_scope_as_login():
    # rest_verify_email was the one anonymous JSON endpoint the branch's
    # throttling hardening didn't reach; it now shares rest_login's scope.
    assert auth_views.rest_verify_email.cls.throttle_classes == [LoginRateThrottle]
    assert LoginRateThrottle.scope == 'login'


def test_verify_email_is_throttled(api, monkeypatch):
    cache.clear()
    monkeypatch.setattr(LoginRateThrottle, 'rate', '2/min')
    try:
        codes = [api.post('/rest-auth/registration/verify-email/', {'key': 'garbage'}).status_code
                 for _i in range(3)]
    finally:
        cache.clear()
    assert codes == [400, 400, 429]


def test_confirm_email_link_activates_and_redirects(api):
    user = User(username='pending', email='p@example.com', is_active=False)
    user.set_password('pw12345678')
    user.save()
    token = _signer().sign(str(user.pk))
    resp = api.get('/account/confirm-email/%s/' % token)
    assert resp.status_code == 302
    assert resp['Location'] == '/login/?email=confirm'
    user.refresh_from_db()
    assert user.is_active is True


def test_confirm_email_link_bad_token_redirects_invalid(api):
    resp = api.get('/account/confirm-email/garbage/')
    assert resp.status_code == 302
    assert resp['Location'] == '/login/?email=invalid'


def test_browser_logout_redirects_home(client):
    user = User.objects.create_user('logout-user', 'lo@example.com', 'pw12345678')
    client.force_login(user)
    resp = client.post('/logout/')
    assert resp.status_code == 302
    assert resp['Location'] == '/'


def test_navbar_logout_form_points_to_logout_url(client):
    user = User.objects.create_user('nav-user', 'nv@example.com', 'pw12345678')
    client.force_login(user)
    # index_view redirects authenticated users to /user_data/, which renders
    # base.html with the authenticated navbar (containing the logout form).
    resp = client.get('/user_data/')
    assert resp.status_code == 200
    assert 'action="/logout/"' in resp.content.decode()


def test_register_rejects_common_password_in_thai(api):
    # CommonPasswordValidator raises "This password is too common."; our
    # locale shadows Django's English fallback so the user sees Thai.
    resp = api.post('/rest-auth/registration/', {
        'email': 'cp@example.com', 'username': 'cp',
        'password1': 'password', 'password2': 'password',
    })
    assert resp.status_code == 400
    assert resp.json()['password'] == ['รหัสผ่านนี้คาดเดาง่ายเกินไป']


def test_register_rejects_numeric_password_in_thai(api):
    resp = api.post('/rest-auth/registration/', {
        'email': 'np@example.com', 'username': 'np',
        'password1': '14725836900', 'password2': '14725836900',
    })
    assert resp.status_code == 400
    assert 'รหัสผ่านต้องไม่เป็นตัวเลขทั้งหมด' in resp.json()['password']


def test_register_rejects_short_password_in_thai(api):
    resp = api.post('/rest-auth/registration/', {
        'email': 'sp@example.com', 'username': 'sp',
        'password1': 'x7', 'password2': 'x7',
    })
    assert resp.status_code == 400
    # MinimumLengthValidator is plural-form for default min_length=8.
    assert any('รหัสผ่านสั้นเกินไป' in msg for msg in resp.json()['password'])
