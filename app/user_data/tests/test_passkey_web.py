import json

import pytest
from django.test import Client

from .conftest import add_passkey

pytestmark = pytest.mark.django_db


def _assertion(client, authenticator, **tamper):
    begin = client.post('/api/passkeys/login/begin/', '{}',
                        content_type='application/json').json()
    return {'challenge_id': begin['challenge_id'],
            'credential': authenticator.assert_(begin['options'], **tamper)}


def _post_json(client, url, body, **extra):
    return client.post(url, json.dumps(body), content_type='application/json', **extra)


def test_web_login_starts_session_and_honours_next(client, alice, authenticator):
    add_passkey(alice, authenticator)
    body = dict(_assertion(client, authenticator), next='/o/authorize/?client_id=x')
    resp = _post_json(client, '/login/passkey/', body)
    assert resp.status_code == 200
    assert resp.json() == {'redirect': '/o/authorize/?client_id=x'}
    assert client.session['_auth_user_id'] == str(alice.pk)


@pytest.mark.parametrize('next_url', [
    'https://evil.example/', '//evil.example', '', None, 5,
    {'a': 1}, [1, 2],
    '\n//evil.example/',      # leading control char before a scheme-relative bypass
    '\x00//evil.example/',    # NUL used the same way
])
def test_web_login_unsafe_next_falls_back_to_root(client, alice, authenticator, next_url):
    add_passkey(alice, authenticator)
    body = dict(_assertion(client, authenticator), next=next_url)
    assert _post_json(client, '/login/passkey/', body).json() == {'redirect': '/'}


def test_web_login_rejects_bad_assertion(client, alice, authenticator):
    add_passkey(alice, authenticator)
    resp = _post_json(client, '/login/passkey/',
                      _assertion(client, authenticator, corrupt_signature=True))
    assert resp.status_code == 400
    assert 'detail' in resp.json()
    assert '_auth_user_id' not in client.session


def test_web_login_inactive_account(client, alice, authenticator):
    add_passkey(alice, authenticator)
    alice.is_active = False
    alice.save()
    assert _post_json(client, '/login/passkey/', _assertion(client, authenticator)).status_code == 400


def test_web_login_requires_csrf(alice, authenticator):
    add_passkey(alice, authenticator)
    csrf_client = Client(enforce_csrf_checks=True)
    resp = _post_json(csrf_client, '/login/passkey/', _assertion(csrf_client, authenticator))
    assert resp.status_code == 403


def test_web_login_accepts_csrf_header(alice, authenticator):
    add_passkey(alice, authenticator)
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.get('/login/')
    token = csrf_client.cookies['csrftoken'].value
    resp = _post_json(csrf_client, '/login/passkey/', _assertion(csrf_client, authenticator),
                      HTTP_X_CSRFTOKEN=token)
    assert resp.status_code == 200


def test_web_login_rejects_get_and_garbage(client):
    assert client.get('/login/passkey/').status_code == 405
    assert client.post('/login/passkey/', 'not json',
                       content_type='application/json').status_code == 400


# --- session fixation --------------------------------------------------------

def test_web_login_cycles_session_key(client, alice, authenticator):
    """login() must never let a pre-existing (e.g. attacker-planted) session
    key survive into an authenticated session -- a login-CSRF-adjacent
    fixation attack plants a known session id in the victim's browser before
    they authenticate, hoping to reuse that same id afterwards. Accessing
    `client.session` (a Django test-client convenience for seeding session
    state before a request) already creates and saves an empty session, so
    the "before" value here is a real key, not None, and login() cycling it
    is what actually protects against fixation, not just a lack of the
    session having existed before.
    """
    add_passkey(alice, authenticator)
    body = _assertion(client, authenticator)
    session_key_before = client.session.session_key
    assert session_key_before
    resp = _post_json(client, '/login/passkey/', body)
    assert resp.status_code == 200
    assert client.session.session_key
    assert client.session.session_key != session_key_before


# --- crafted-body hardening: anonymous, unthrottled endpoint must never 500 -

@pytest.mark.parametrize('body', [[1, 2], 'just a string', 42, True])
def test_web_login_non_object_json_body_is_400(client, body):
    resp = client.post('/login/passkey/', json.dumps(body), content_type='application/json')
    assert resp.status_code == 400
    assert '_auth_user_id' not in client.session


@pytest.mark.parametrize('challenge_id', [{'a': 1}, [1, 2], 42, None])
def test_web_login_crafted_challenge_id_types_are_400(client, challenge_id):
    resp = _post_json(client, '/login/passkey/', {'challenge_id': challenge_id, 'credential': {}})
    assert resp.status_code == 400


@pytest.mark.parametrize('credential', ['not-a-dict', [1, 2], None])
def test_web_login_crafted_credential_types_are_400(client, credential):
    begin = client.post('/api/passkeys/login/begin/', '{}',
                        content_type='application/json').json()
    resp = _post_json(client, '/login/passkey/',
                      {'challenge_id': begin['challenge_id'], 'credential': credential})
    assert resp.status_code == 400


def _nested_body(depth):
    return '{"a":' * depth + '1' + '}' * depth


def test_web_login_deeply_nested_json_body_is_400_not_500(client):
    # Same nesting-depth reasoning as user_data/tests/test_drf_handlers.py:
    # DRF's global EXCEPTION_HANDLER does not cover this view at all (it is
    # a plain Django view, never dispatched through DRF's APIView), so the
    # RecursionError json.loads() raises on a pathologically deep body has
    # to be caught locally, inside json_body() itself.
    resp = client.post('/login/passkey/', _nested_body(20000), content_type='application/json')
    assert resp.status_code == 400
    assert '_auth_user_id' not in client.session


def test_web_login_huge_body_is_400_not_500(client):
    # Bigger than DATA_UPLOAD_MAX_MEMORY_SIZE (2.5MB default): Django's own
    # HttpRequest.body raises RequestDataTooBig (a SuspiciousOperation)
    # before json_body() ever sees the bytes, and Django's exception-to-
    # response handling turns a SuspiciousOperation into a plain 400 on its
    # own -- this pins that behaviour for this view rather than assuming it.
    huge = json.dumps({'padding': 'x' * (6 * 1024 * 1024)})
    resp = client.post('/login/passkey/', huge, content_type='application/json')
    assert resp.status_code == 400
    assert '_auth_user_id' not in client.session
