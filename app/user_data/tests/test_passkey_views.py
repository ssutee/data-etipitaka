import logging

import pytest
from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from django.utils import translation
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from user_data import passkey_views
from user_data.passkey_views import PasskeyRateThrottle

from .conftest import add_passkey, make_oauth_token

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


# --- anonymous pinning: a caller's own credentials must never matter -------
#
# Every view is decorated @authentication_classes([]) -- these endpoints have
# no notion of "who is calling". The dangerous mutation is one that quietly
# adds an authentication class back (e.g. copy-pasting TokenAuthentication
# from another view in this module) while leaving permission_classes([])
# alone: nothing about permissions would catch it, since an empty permission
# list still lets the request through. A garbage credential of a kind that
# *is* recognised by the class being (hypothetically) added back is what
# catches it: TokenAuthentication.authenticate_credentials() raises
# AuthenticationFailed (401) for an unrecognised key, BasicAuthentication
# raises the same for a username/password that doesn't exist, and
# SessionAuthentication's own CSRF check raises PermissionDenied (403) for a
# force_login()'d session with no CSRF token attached -- and each of those
# exceptions is raised during DRF's initial() step, before the view body
# ever runs, so no amount of code inside the view could prevent it once the
# decorator regresses. django-oauth-toolkit's own authenticator is the one
# exception: it returns None for an unrecognised bearer token exactly like
# no authenticator being configured at all, so no request/response shape can
# ever reveal that mutation -- test_anonymous_views_declare_no_authenticator
# below is what actually guards against it (and against all the others too).
#
# The plain 'session' client below does NOT catch a SessionAuthentication
# regression: DRF's default test client has enforce_csrf_checks=False, so
# CSRF is never validated through it regardless of which authenticators are
# configured. 'csrf_session' is the one built with enforce_csrf_checks=True.

CREDENTIAL_LABELS = ['valid_token', 'garbage_token', 'garbage_basic', 'oauth_bearer',
                     'session', 'csrf_session']


def _credentialed_client(alice, label):
    client = APIClient(enforce_csrf_checks=(label == 'csrf_session'))
    if label == 'valid_token':
        client.credentials(HTTP_AUTHORIZATION='Token ' + alice.auth_token.key)
    elif label == 'garbage_token':
        client.credentials(HTTP_AUTHORIZATION='Token not-a-real-token')
    elif label == 'garbage_basic':
        # base64("nope:nope") -- a well-formed but nonexistent credential.
        client.credentials(HTTP_AUTHORIZATION='Basic bm9wZTpub3Bl')
    elif label == 'oauth_bearer':
        client.credentials(HTTP_AUTHORIZATION='Bearer ' + make_oauth_token(alice).token)
    elif label in ('session', 'csrf_session'):
        client.force_login(alice)
    return client


@pytest.mark.parametrize('label', CREDENTIAL_LABELS)
def test_login_begin_ignores_caller_credentials(alice, label):
    client = _credentialed_client(alice, label)
    resp = _post(client, '/api/passkeys/login/begin/')
    assert resp.status_code == 200


@pytest.mark.parametrize('label', CREDENTIAL_LABELS)
def test_signup_begin_ignores_caller_credentials(alice, label):
    client = _credentialed_client(alice, label)
    resp = _signup_begin(client, username='cred_probe', email='cred_probe@example.com')
    assert resp.status_code == 200


@pytest.mark.parametrize('label', CREDENTIAL_LABELS)
def test_login_finish_error_body_unchanged_by_caller_credentials(alice, authenticator, label):
    add_passkey(alice, authenticator)
    baseline = _login(APIClient(), authenticator, corrupt_signature=True)
    client = _credentialed_client(alice, label)
    resp = _login(client, authenticator, corrupt_signature=True)
    assert resp.status_code == baseline.status_code == 400
    assert resp.json() == baseline.json()


@pytest.mark.parametrize('label', CREDENTIAL_LABELS)
def test_signup_finish_error_body_unchanged_by_caller_credentials(alice, authenticator, label):
    def _bad_registration(client, username, email):
        body = _signup_begin(client, username=username, email=email).json()
        return _post(client, '/api/passkeys/signup/finish/', {
            'challenge_id': body['challenge_id'],
            'credential': authenticator.register(body['options'], uv=False)})

    baseline = _bad_registration(APIClient(), 'cred_probe2', 'cred_probe2@example.com')
    client = _credentialed_client(alice, label)
    resp = _bad_registration(client, 'cred_probe3', 'cred_probe3@example.com')
    assert resp.status_code == baseline.status_code == 400
    assert resp.json() == baseline.json()


@pytest.mark.parametrize('name', ['login_begin', 'login_finish',
                                  'signup_begin', 'signup_finish'])
def test_anonymous_views_declare_no_authenticator(name):
    """The direct guard: whatever a probe request can or can't reveal (an
    unrecognised OAuth2 bearer token reveals nothing at all -- DOT's
    authenticator returns None for it exactly like no authenticator being
    configured), the view's own declared classes are always inspectable.
    """
    view = getattr(passkey_views, name)
    assert view.cls.authentication_classes == []
    assert view.cls.permission_classes == []


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
