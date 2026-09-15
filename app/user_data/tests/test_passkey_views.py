import logging

import pytest
from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from django.utils import translation
from rest_framework.authtoken.models import Token

from user_data.passkey_views import PasskeyRateThrottle

from .conftest import add_passkey

pytestmark = pytest.mark.django_db


def _post(client, url, body=None):
    return client.post(url, body if body is not None else {}, format='json')


def _login(client, authenticator, **tamper):
    begin = _post(client, '/api/passkeys/login/begin/').json()
    return _post(client, '/api/passkeys/login/finish/', {
        'challenge_id': begin['challenge_id'],
        'credential': authenticator.assert_(begin['options'], **tamper)})


def _signup_begin(client, username='newbie', email='n@example.com'):
    return _post(client, '/api/passkeys/signup/begin/', {'username': username, 'email': email})


# --- login ------------------------------------------------------------------

def test_login_begin(api):
    resp = _post(api, '/api/passkeys/login/begin/')
    assert resp.status_code == 200
    assert resp.json()['challenge_id']
    assert resp.json()['options']['rpId'] == 'data.etipitaka.com'


def test_login_finish_returns_same_token_as_password_login(api, alice, authenticator):
    add_passkey(alice, authenticator)
    resp = _login(api, authenticator)
    assert resp.status_code == 200
    assert resp.json() == {'key': Token.objects.get(user=alice).key}


def test_login_finish_creates_token_when_missing(api, alice, authenticator):
    add_passkey(alice, authenticator)
    Token.objects.filter(user=alice).delete()
    assert _login(api, authenticator).json()['key'] == Token.objects.get(user=alice).key


def test_login_finish_bad_assertion_matches_password_login_error(api, alice, authenticator):
    add_passkey(alice, authenticator)
    resp = _login(api, authenticator, corrupt_signature=True)
    password = api.post('/rest-auth/login/', {'username': 'alice', 'password': 'wrong'})
    assert resp.status_code == 400
    assert resp.json() == password.json()


def test_login_finish_inactive_account(api, alice, authenticator):
    add_passkey(alice, authenticator)
    alice.is_active = False
    alice.save()
    resp = _login(api, authenticator)
    with translation.override('th'):
        expected = translation.gettext('This account is not active. Please verify your email.')
    assert resp.status_code == 400
    assert resp.json() == {'non_field_errors': [expected]}


def test_login_finish_non_object_body(api):
    assert _post(api, '/api/passkeys/login/finish/', [1, 2]).status_code == 400


# --- signup -------------------------------------------------------------

def test_signup_flow_sends_verification_email(api, authenticator):
    begin = _signup_begin(api)
    assert begin.status_code == 200
    body = begin.json()
    resp = _post(api, '/api/passkeys/signup/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options']), 'name': 'Phone'})
    assert resp.status_code == 201
    assert User.objects.get(username='newbie').is_active is False
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ['n@example.com']


def test_signup_begin_field_errors(api, alice):
    resp = _signup_begin(api, username='alice', email='bad')
    assert resp.status_code == 400
    assert set(resp.json()) == {'username', 'email'}


def test_signup_finish_bad_response(api, authenticator):
    body = _signup_begin(api).json()
    resp = _post(api, '/api/passkeys/signup/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options'], uv=False)})
    assert resp.status_code == 400
    assert 'detail' in resp.json()


def test_signup_finish_username_taken_since_begin(api, authenticator):
    body = _signup_begin(api).json()
    User.objects.create_user('newbie', 'x@example.com', 'pw12345678')
    resp = _post(api, '/api/passkeys/signup/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options'])})
    assert resp.status_code == 400
    assert 'username' in resp.json()


# --- signup: verification email must not turn a committed account into a 500 -

def test_signup_finish_still_201_when_verification_email_raises(api, authenticator, monkeypatch, caplog):
    """The account (and its passkey) are already committed by the time the
    verification email is sent -- a mail outage must not 500 back a
    committed signup, since the username is now taken and there is no
    resend endpoint the user could retry through.
    """
    def _boom(request, user):
        raise RuntimeError('smtp is down')

    monkeypatch.setattr('user_data.passkey_views._send_verification_email', _boom)
    body = _signup_begin(api).json()
    with caplog.at_level(logging.ERROR):
        resp = _post(api, '/api/passkeys/signup/finish/', {
            'challenge_id': body['challenge_id'],
            'credential': authenticator.register(body['options']), 'name': 'Phone'})
    assert resp.status_code == 201
    assert User.objects.filter(username='newbie').exists()
    assert any(record.levelno >= logging.ERROR for record in caplog.records)


# --- crafted-body hardening: anonymous endpoints must never 500 -------------

_ALL_URLS = [
    '/api/passkeys/login/begin/',
    '/api/passkeys/login/finish/',
    '/api/passkeys/signup/begin/',
    '/api/passkeys/signup/finish/',
]


@pytest.mark.parametrize('url', _ALL_URLS)
@pytest.mark.parametrize('body', [[1, 2], 'just a string', 42, True])
def test_non_object_json_body_is_400(api, url, body):
    assert _post(api, url, body).status_code == 400


@pytest.mark.parametrize('url', ['/api/passkeys/login/finish/', '/api/passkeys/signup/finish/'])
@pytest.mark.parametrize('challenge_id', [{'a': 1}, [1, 2], 42, None])
def test_crafted_challenge_id_types_are_400(api, url, challenge_id):
    resp = _post(api, url, {'challenge_id': challenge_id, 'credential': {}})
    assert resp.status_code == 400


@pytest.mark.parametrize('credential', ['not-a-dict', [1, 2], None])
def test_login_finish_crafted_credential_types_are_400(api, credential):
    begin = _post(api, '/api/passkeys/login/begin/').json()
    resp = _post(api, '/api/passkeys/login/finish/', {
        'challenge_id': begin['challenge_id'], 'credential': credential})
    assert resp.status_code == 400


@pytest.mark.parametrize('credential', ['not-a-dict', [1, 2], None])
def test_signup_finish_crafted_credential_types_are_400(api, credential):
    begin = _signup_begin(api).json()
    resp = _post(api, '/api/passkeys/signup/finish/', {
        'challenge_id': begin['challenge_id'], 'credential': credential})
    assert resp.status_code == 400


@pytest.mark.parametrize('name', [{'a': 1}, 'x' * 5000])
def test_signup_finish_crafted_name_is_sanitized_not_500(api, authenticator, name):
    """clean_name() (Task 1-10) already sanitizes a non-str or over-long
    name rather than rejecting it, so a crafted name is not a 400 case here
    -- the requirement is just that it can never reach a 500. Registration
    still succeeds with a cleaned/default name.
    """
    body = _signup_begin(api).json()
    resp = _post(api, '/api/passkeys/signup/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options']), 'name': name})
    assert resp.status_code == 201


@pytest.mark.parametrize('field,value', [
    ('username', {'a': 1}), ('username', [1, 2]),
    ('email', {'a': 1}), ('email', [1, 2]),
])
def test_signup_begin_crafted_identity_types_are_400(api, field, value):
    body = {'username': 'newbie', 'email': 'n@example.com'}
    body[field] = value
    resp = _post(api, '/api/passkeys/signup/begin/', body)
    assert resp.status_code == 400


@pytest.mark.parametrize('url', _ALL_URLS)
def test_malformed_json_body_is_400(api, url):
    resp = api.post(url, '{not valid json', content_type='application/json')
    assert resp.status_code == 400


# --- throttling -------------------------------------------------------------

def test_passkey_throttle_scope_resolves_from_settings():
    from django.conf import settings
    assert PasskeyRateThrottle.scope == 'passkey'
    assert 'passkey' in settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']


def test_passkey_endpoints_are_throttled(api, monkeypatch):
    cache.clear()
    monkeypatch.setattr(PasskeyRateThrottle, 'rate', '2/min')
    try:
        codes = [_post(api, '/api/passkeys/login/begin/').status_code for _i in range(3)]
    finally:
        cache.clear()
    assert codes == [200, 200, 429]
