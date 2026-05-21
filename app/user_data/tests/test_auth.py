import pytest
from django.contrib.auth.models import User
from django.core import mail
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from user_data.auth_views import _signer

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
