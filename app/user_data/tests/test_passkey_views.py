import logging
import os
import re
from importlib import import_module
from pathlib import Path

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from django.test import Client, override_settings
from django.utils import translation
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.test import APIClient

from user_data import passkey_views
from user_data.models import Passkey
from user_data.passkey_service import PASSKEY_MAX_PER_USER
from user_data.passkey_views import (PasskeyDesktopThrottle,
                                     PasskeyPasswordThrottle, PasskeyRateThrottle)

from .conftest import add_passkey, make_oauth_token
from .soft_authenticator import SoftAuthenticator

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


def test_signup_begin_rejects_username_differing_only_by_case(api):
    User.objects.create_user('newbie', 'first@example.com', 'pw12345678')
    resp = _signup_begin(api, username='Newbie', email='second@example.com')
    assert resp.status_code == 400
    assert 'username' in resp.json()


def test_signup_begin_rejects_email_differing_only_by_case(api):
    User.objects.create_user('someone', 'N@x.com', 'pw12345678')
    resp = _signup_begin(api, username='newbie', email='n@x.com')
    assert resp.status_code == 400
    assert 'email' in resp.json()


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


@pytest.mark.parametrize('scope', ['login', 'passkey', 'passkey_password', 'passkey_desktop'])
def test_throttle_rate_is_declared_not_just_created_by_the_test_override(scope):
    """The *_scope_resolves_from_settings membership checks are weaker than
    they look: settings.py's pytest branch *assigns* DEFAULT_THROTTLE_RATES[
    scope] = None for every one of these scopes, which creates the key
    whether or not the shipped settings declare a rate at all -- so `in`
    would still hold after the real rate was deleted, and every request in
    production would then go unlimited. Assert the shipped declaration
    itself. The pattern is anchored to the start of a line, so neither the
    override's `REST_FRAMEWORK[...][...] = None` form nor a commented-out
    entry can satisfy it -- only the live dict entry can.
    """
    # os.environ, not settings.SETTINGS_MODULE: conftest's autouse
    # _passkey_settings fixture puts a UserSettingsHolder in front of the
    # real settings for every test here, and that holder reports
    # SETTINGS_MODULE as None.
    source = Path(import_module(os.environ['DJANGO_SETTINGS_MODULE']).__file__).read_text()
    pattern = rf"^[ \t]*'{re.escape(scope)}':\s*'\d+/(sec|min|hour|day)'"
    assert re.search(pattern, source, re.MULTILINE)


def test_passkey_endpoints_are_throttled(api, monkeypatch):
    cache.clear()
    monkeypatch.setattr(PasskeyRateThrottle, 'rate', '2/min')
    try:
        codes = [_post(api, '/api/passkeys/login/begin/').status_code for _i in range(3)]
    finally:
        cache.clear()
    assert codes == [200, 200, 429]


def _spoofed(client, xff):
    return client.post('/api/passkeys/login/begin/', {}, format='json',
                       HTTP_X_FORWARDED_FOR=xff)


def test_num_proxies_pins_ident_to_real_client_despite_spoofed_forwarded_for(api, monkeypatch):
    """settings.py sets REST_FRAMEWORK['NUM_PROXIES'] = 1 because nginx.conf's
    $proxy_add_x_forwarded_for always appends the real client address as the
    LAST X-Forwarded-For entry (see that setting's comment) -- so two
    requests that share a real client but spoof different *leading* entries
    must still land in the same throttle bucket.
    """
    assert settings.REST_FRAMEWORK['NUM_PROXIES'] == 1
    cache.clear()
    monkeypatch.setattr(PasskeyRateThrottle, 'rate', '1/min')
    try:
        first = _spoofed(api, '203.0.113.5, 10.0.0.5')
        second = _spoofed(api, '198.51.100.9, 10.0.0.5')
    finally:
        cache.clear()
    assert (first.status_code, second.status_code) == (200, 429)


def test_forwarded_for_bypasses_throttle_without_num_proxies(api, monkeypatch):
    """The bug NUM_PROXIES: 1 fixes, pinned so it cannot silently come back:
    with NUM_PROXIES unset (DRF's own default), get_ident() uses the whole
    raw X-Forwarded-For string as the cache-key ident, so a caller can dodge
    the bucket by varying that header on its own request -- even though, as
    the previous test shows, the real client (the trailing entry nginx
    appends) never changed between the two requests.
    """
    cache.clear()
    monkeypatch.setattr(PasskeyRateThrottle, 'rate', '1/min')
    rf_without_num_proxies = {k: v for k, v in settings.REST_FRAMEWORK.items()
                              if k != 'NUM_PROXIES'}
    try:
        with override_settings(REST_FRAMEWORK=rf_without_num_proxies):
            first = _spoofed(api, '203.0.113.5, 10.0.0.5')
            second = _spoofed(api, '198.51.100.9, 10.0.0.5')
    finally:
        cache.clear()
    assert (first.status_code, second.status_code) == (200, 200)


# --- account endpoints ------------------------------------------------------

def _register_via_api(client, authenticator, proof):
    begin = _post(client, '/api/passkeys/register/begin/', proof)
    assert begin.status_code == 200, begin.content
    body = begin.json()
    return _post(client, '/api/passkeys/register/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options']), 'name': 'Phone'})


def test_register_with_password_step_up(auth_alice, alice, authenticator):
    resp = _register_via_api(auth_alice, authenticator, {'password': 'alicepass123'})
    assert resp.status_code == 201
    assert resp.json()['name'] == 'Phone'
    assert alice.passkeys.count() == 1


@pytest.mark.parametrize('proof', [{}, {'password': 'wrong'}, {'step_up': 'x'}])
def test_register_rejects_missing_or_wrong_step_up(auth_alice, proof):
    assert _post(auth_alice, '/api/passkeys/register/begin/', proof).status_code == 400


def test_register_with_passkey_step_up(auth_alice, alice, authenticator):
    add_passkey(alice, authenticator)
    alice.set_unusable_password()
    alice.save()
    begin = _post(APIClient(), '/api/passkeys/login/begin/').json()
    step_up = {'challenge_id': begin['challenge_id'],
               'credential': authenticator.assert_(begin['options'])}
    resp = _register_via_api(auth_alice, SoftAuthenticator(), {'step_up': step_up})
    assert resp.status_code == 201
    assert alice.passkeys.count() == 2


def test_register_finish_bad_response(auth_alice, authenticator):
    body = _post(auth_alice, '/api/passkeys/register/begin/',
                 {'password': 'alicepass123'}).json()
    resp = _post(auth_alice, '/api/passkeys/register/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options'], uv=False)})
    assert resp.status_code == 400


ACCOUNT_ENDPOINTS = [
    ('get', '/api/passkeys/'), ('post', '/api/passkeys/register/begin/'),
    ('post', '/api/passkeys/register/finish/'), ('patch', '/api/passkeys/1/'),
    ('delete', '/api/passkeys/1/'), ('post', '/api/passkeys/password/remove/')]


@pytest.mark.parametrize('method,url', ACCOUNT_ENDPOINTS)
def test_account_endpoints_reject_anonymous(method, url):
    assert getattr(APIClient(), method)(url, {}, format='json').status_code == 401


@pytest.mark.parametrize('method,url', ACCOUNT_ENDPOINTS)
def test_account_endpoints_reject_oauth_bearer(oauth_alice, method, url):
    assert getattr(oauth_alice, method)(url, {}, format='json').status_code == 401


def test_session_auth_is_accepted(client, alice):
    client.force_login(alice)
    assert client.get('/api/passkeys/').status_code == 200


# register_finish (POST) and passkey_detail (PATCH, DELETE) were, before
# this parametrization, never exercised over a session at all -- neither
# CSRF-checked nor otherwise -- so a regression that dropped
# @authentication_classes from either view (which makes a session caller
# anonymous, and IsAuthenticated then 401s before CSRF is ever checked)
# passed the whole suite silently. Each row here drives the real Django
# CSRF middleware through SessionAuthentication.enforce_csrf, the same path
# a browser hits, rather than only asserting the view's declared classes.
CSRF_PROTECTED_ACCOUNT_REQUESTS = [
    ('post', '/api/passkeys/register/begin/', {'password': 'alicepass123'}),
    ('post', '/api/passkeys/register/finish/', {'challenge_id': 'x', 'credential': {}}),
    ('patch', '/api/passkeys/1/', {'name': 'Laptop'}),
    ('delete', '/api/passkeys/1/', None),
    ('post', '/api/passkeys/password/remove/', {'password': 'alicepass123'}),
]


@pytest.mark.parametrize('method,url,body', CSRF_PROTECTED_ACCOUNT_REQUESTS)
def test_session_requires_csrf(alice, method, url, body):
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(alice)
    resp = getattr(csrf_client, method)(url, body or '', content_type='application/json')
    assert resp.status_code == 403


def test_list_rename_delete(auth_alice, alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    url = '/api/passkeys/%d/' % passkey.pk
    listing = auth_alice.get('/api/passkeys/').json()
    assert listing['has_password'] is True
    assert [p['id'] for p in listing['passkeys']] == [passkey.pk]
    renamed = auth_alice.patch(url, {'name': 'Laptop'}, format='json')
    assert renamed.status_code == 200 and renamed.json()['name'] == 'Laptop'
    assert auth_alice.patch(url, {'name': ' '}, format='json').status_code == 400
    assert auth_alice.delete(url).status_code == 204
    assert auth_alice.delete(url).status_code == 404


def test_other_users_passkey_is_404(auth_alice, bob, authenticator):
    passkey = add_passkey(bob, authenticator)
    assert auth_alice.delete('/api/passkeys/%d/' % passkey.pk).status_code == 404


def test_remove_password_then_last_passkey_is_guarded(auth_alice, alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    remove = '/api/passkeys/password/remove/'
    assert _post(auth_alice, remove, {'password': 'wrong'}).status_code == 400
    resp = _post(auth_alice, remove, {'password': 'alicepass123'})
    assert resp.status_code == 200 and resp.json() == {'has_password': False}
    assert auth_alice.delete('/api/passkeys/%d/' % passkey.pk).status_code == 409
    assert _post(auth_alice, remove, {'password': 'alicepass123'}).status_code == 409


def test_remove_password_keeps_session_signed_in(client, alice, authenticator):
    add_passkey(alice, authenticator)
    client.force_login(alice)
    resp = client.post('/api/passkeys/password/remove/', {'password': 'alicepass123'},
                       content_type='application/json')
    assert resp.status_code == 200
    assert client.get('/api/passkeys/').status_code == 200


def test_remove_password_via_token_does_not_touch_session(auth_alice, alice, authenticator,
                                                           monkeypatch):
    """`request.successful_authenticator` -- not e.g. `hasattr(request, 'session')`,
    which a Token-authenticated request still has, just an anonymous one -- is
    what must gate update_session_auth_hash: a token-authenticated removal
    must never touch (or even look at) the caller's session.
    """
    add_passkey(alice, authenticator)
    calls = []
    monkeypatch.setattr(passkey_views, 'update_session_auth_hash',
                        lambda request, user: calls.append(user))
    resp = _post(auth_alice, '/api/passkeys/password/remove/', {'password': 'alicepass123'})
    assert resp.status_code == 200
    assert calls == []


def test_remove_password_via_session_updates_session_auth_hash(client, alice, authenticator,
                                                                monkeypatch):
    add_passkey(alice, authenticator)
    client.force_login(alice)
    calls = []
    monkeypatch.setattr(passkey_views, 'update_session_auth_hash',
                        lambda request, user: calls.append(user))
    resp = client.post('/api/passkeys/password/remove/', {'password': 'alicepass123'},
                       content_type='application/json')
    assert resp.status_code == 200
    assert calls == [alice]


# --- passkey cap: TooManyPasskeys must be a 409, never a 500 ----------------

def _fill_passkeys(user, count=PASSKEY_MAX_PER_USER):
    """Reach the passkey cap with plain ORM rows -- running `count` real
    WebAuthn ceremonies would work too but is needlessly slow."""
    Passkey.objects.bulk_create([
        Passkey(user=user, credential_id='dummy-%d-%d' % (user.pk, i),
               public_key=b'', sign_count=0, transports=[], aaguid='', name='Dummy')
        for i in range(count)])


def test_register_begin_rejects_when_cap_already_reached(auth_alice, alice):
    _fill_passkeys(alice)
    resp = _post(auth_alice, '/api/passkeys/register/begin/', {'password': 'alicepass123'})
    assert resp.status_code == 409


def test_register_finish_rejects_when_cap_reached_between_begin_and_finish(
        auth_alice, alice, authenticator):
    begin = _post(auth_alice, '/api/passkeys/register/begin/', {'password': 'alicepass123'})
    assert begin.status_code == 200
    body = begin.json()
    _fill_passkeys(alice)  # fills the cap after begin, before finish
    resp = _post(auth_alice, '/api/passkeys/register/finish/', {
        'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options']), 'name': 'Phone'})
    assert resp.status_code == 409


# --- account endpoints: throttled, like every other passkey endpoint -------

@pytest.mark.parametrize('name', ['passkey_list', 'passkey_detail', 'register_finish'])
def test_account_endpoints_are_throttled(name):
    view = getattr(passkey_views, name)
    assert view.cls.throttle_classes == [PasskeyRateThrottle]


@pytest.mark.parametrize('name', ['register_begin', 'password_remove'])
def test_password_bearing_endpoints_have_both_throttles(name):
    # register_begin's step-up and password_remove both accept a password
    # guess -- see PasskeyPasswordThrottle's docstring -- so they carry the
    # tighter passkey_password throttle ALONGSIDE the general one, not
    # instead of it.
    view = getattr(passkey_views, name)
    assert view.cls.throttle_classes == [PasskeyRateThrottle, PasskeyPasswordThrottle]


@pytest.mark.parametrize('name', ['passkey_list', 'passkey_detail', 'register_finish',
                                  'login_begin', 'login_finish', 'signup_begin', 'signup_finish',
                                  'desktop_begin', 'desktop_poll'])
def test_only_password_bearing_endpoints_have_the_password_throttle(name):
    view = getattr(passkey_views, name)
    assert PasskeyPasswordThrottle not in view.cls.throttle_classes


def test_passkey_password_throttle_scope_resolves_from_settings():
    assert PasskeyPasswordThrottle.scope == 'passkey_password'
    assert 'passkey_password' in settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']


def test_register_begin_is_throttled_by_the_password_scope(auth_alice, monkeypatch):
    """The tighter passkey_password bucket must trip well before the
    general passkey one would -- set PasskeyRateThrottle generously loose
    so only PasskeyPasswordThrottle can be what trips here.
    """
    cache.clear()
    monkeypatch.setattr(PasskeyRateThrottle, 'rate', '1000/min')
    monkeypatch.setattr(PasskeyPasswordThrottle, 'rate', '2/min')
    try:
        codes = [_post(auth_alice, '/api/passkeys/register/begin/').status_code
                 for _i in range(3)]
    finally:
        cache.clear()
    # Every request here is missing password/step_up (a 400, not throttled)
    # until the bucket trips.
    assert codes == [400, 400, 429]


def test_password_remove_is_throttled_by_the_password_scope(auth_alice, monkeypatch):
    cache.clear()
    monkeypatch.setattr(PasskeyRateThrottle, 'rate', '1000/min')
    monkeypatch.setattr(PasskeyPasswordThrottle, 'rate', '2/min')
    try:
        codes = [_post(auth_alice, '/api/passkeys/password/remove/').status_code
                 for _i in range(3)]
    finally:
        cache.clear()
    # alice (no passkey added) hits the lockout guard (409) on every
    # request until the bucket trips -- not throttled either way, so this
    # still isolates the throttle's own behaviour.
    assert codes == [409, 409, 429]


# --- desktop pairing endpoints carry their own scope ------------------------

@pytest.mark.parametrize('name', ['desktop_begin', 'desktop_poll'])
def test_desktop_endpoints_are_throttled(name):
    """Both legs are anonymous and unauthenticated -- begin creates a row on
    demand and poll hands out a DRF token -- so this decorator is the only
    application-layer limiter they have. Without this assertion, deleting it
    from either view leaves the whole suite green.
    """
    view = getattr(passkey_views, name)
    assert view.cls.throttle_classes == [PasskeyDesktopThrottle]


def test_passkey_desktop_throttle_scope_resolves_from_settings():
    assert PasskeyDesktopThrottle.scope == 'passkey_desktop'
    assert 'passkey_desktop' in settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']


def test_desktop_begin_is_throttled_by_the_desktop_scope(api, monkeypatch):
    """settings.py nulls this scope's rate under pytest, which makes
    allow_request() unconditionally true -- so a monkeypatched rate is the
    only way to watch the throttle actually run. Same pattern as
    test_register_begin_is_throttled_by_the_password_scope above.
    """
    cache.clear()
    monkeypatch.setattr(PasskeyDesktopThrottle, 'rate', '2/min')
    try:
        codes = [_post(api, '/api/passkeys/desktop/begin/').status_code for _i in range(3)]
    finally:
        cache.clear()
    assert codes == [200, 200, 429]


def test_desktop_poll_is_throttled_by_the_desktop_scope(api, monkeypatch):
    cache.clear()
    monkeypatch.setattr(PasskeyDesktopThrottle, 'rate', '2/min')
    try:
        codes = [_post(api, '/api/passkeys/desktop/poll/',
                       {'device_code': 'nope'}).status_code for _i in range(3)]
    finally:
        cache.clear()
    # An unknown device code is a plain 400 -- not throttled either way, so
    # the 429 is unambiguously the throttle's doing.
    assert codes == [400, 400, 429]


@pytest.mark.parametrize('name', ['passkey_list', 'passkey_detail', 'register_begin',
                                  'register_finish', 'password_remove'])
def test_account_endpoints_declare_their_authenticators(name):
    """Pins the exact authenticator list and its order on every account view.

    This is a structural mutation-catcher, not a behavioural one: it does
    not send a request, so it catches a regression a green suite could
    otherwise miss -- e.g. dropping @authentication_classes from
    register_finish or passkey_detail, which would make a session caller
    anonymous there (a 401 from IsAuthenticated, before CSRF is even
    checked) while every *other* test still force_login()s a client whose
    Token credential (from the `client`/`alice` fixtures' auth_token) can
    make Token-based tests pass regardless.

    Token must come before Session: when every configured authenticator
    fails to authenticate a request, DRF's exception handler takes the
    `WWW-Authenticate` challenge header from the *first* authenticator in
    the list to answer with a 401. SessionAuthentication declares none, so
    if it came first, an unauthenticated caller with no credentials at all
    would get a bare 403 instead of DRF's normal 401 -- exactly backwards
    from what test_account_endpoints_reject_anonymous already pins.

    OAuth2Authentication must never appear here at all: these are the
    account-management endpoints an OAuth bearer token must never reach
    (see the module docstring and test_account_endpoints_reject_oauth_bearer).
    """
    view = getattr(passkey_views, name)
    assert view.cls.authentication_classes == [TokenAuthentication, SessionAuthentication]
    assert view.cls.permission_classes == [IsAuthenticated]


# --- account endpoints: crafted input must never reach a 500 ----------------

@pytest.mark.parametrize('password', [{'a': 1}, [1, 2], 42, None])
def test_register_begin_rejects_crafted_password_types(auth_alice, password):
    resp = _post(auth_alice, '/api/passkeys/register/begin/', {'password': password})
    assert resp.status_code == 400


@pytest.mark.parametrize('step_up', [{'a': 1}, [1, 2], 42, None])
def test_register_begin_rejects_crafted_step_up_types(auth_alice, step_up):
    resp = _post(auth_alice, '/api/passkeys/register/begin/', {'step_up': step_up})
    assert resp.status_code == 400


@pytest.mark.parametrize('step_up', [
    {'challenge_id': 'not-a-real-id', 'credential': {}},
    {'challenge_id': None, 'credential': 'not-a-dict'},
    {'challenge_id': {'a': 1}, 'credential': [1, 2]},
    {'challenge_id': 'not-a-real-id', 'credential': {'garbage': True}},
])
def test_register_begin_rejects_junk_step_up_assertion(auth_alice, step_up):
    resp = _post(auth_alice, '/api/passkeys/register/begin/', {'step_up': step_up})
    assert resp.status_code == 400


@pytest.mark.parametrize('name', [{'a': 1}, 42, ['x']])
def test_patch_rejects_crafted_name_types_with_invalid_name(auth_alice, alice, authenticator,
                                                             name):
    passkey = add_passkey(alice, authenticator)
    resp = auth_alice.patch('/api/passkeys/%d/' % passkey.pk, {'name': name}, format='json')
    assert resp.status_code == 400
    assert 'name' in resp.json()


def test_patch_with_no_name_key_is_400(auth_alice, alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    resp = auth_alice.patch('/api/passkeys/%d/' % passkey.pk, {}, format='json')
    assert resp.status_code == 400
    assert 'name' in resp.json()


ACCOUNT_BODY_ENDPOINTS = [
    ('post', '/api/passkeys/register/begin/'),
    ('post', '/api/passkeys/register/finish/'),
    ('patch', '/api/passkeys/1/'),
    ('post', '/api/passkeys/password/remove/'),
]


@pytest.mark.parametrize('method,url', ACCOUNT_BODY_ENDPOINTS)
@pytest.mark.parametrize('body', [[1, 2], 'just a string', 42, True])
def test_account_endpoints_reject_non_object_body(auth_alice, method, url, body):
    assert getattr(auth_alice, method)(url, body, format='json').status_code == 400


def test_passkey_list_rejects_non_object_body(auth_alice):
    resp = auth_alice.generic('GET', '/api/passkeys/', data='[1, 2]',
                              content_type='application/json')
    assert resp.status_code == 400


def test_passkey_delete_rejects_non_object_body(auth_alice, alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    resp = auth_alice.delete('/api/passkeys/%d/' % passkey.pk, [1, 2], format='json')
    assert resp.status_code == 400
    # the crafted body must not have deleted the passkey it never named
    assert Passkey.objects.filter(pk=passkey.pk).exists()


@pytest.mark.parametrize('method,url', ACCOUNT_ENDPOINTS)
def test_account_endpoints_malformed_json_body_is_400(auth_alice, method, url):
    resp = auth_alice.generic(method.upper(), url, data='{not valid json',
                              content_type='application/json')
    assert resp.status_code == 400
