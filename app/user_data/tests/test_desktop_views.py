import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient

from user_data import desktop_pairing
from user_data.models import DesktopPairing

BEGIN = '/api/passkeys/desktop/begin/'
POLL = '/api/passkeys/desktop/poll/'


@pytest.fixture
def api():
    return APIClient()


@pytest.mark.django_db
def test_begin_returns_the_handshake(api, settings):
    response = api.post(BEGIN, {}, format='json')

    assert response.status_code == 200
    body = response.json()
    assert len(body['device_code']) >= 40
    assert body['interval'] == 5
    assert body['expires_in'] == settings.PASSKEY_DESKTOP_TTL
    # user_code is the human-facing dashed form, and the URL carries it.
    assert '-' in body['user_code']
    assert body['user_code'] in body['verification_url']
    assert body['verification_url'].startswith('https://')
    assert '/desktop/' in body['verification_url']


@pytest.mark.django_db
def test_begin_rejects_a_non_object_body(api):
    assert api.post(BEGIN, [1, 2], format='json').status_code == 400


@pytest.mark.django_db
def test_poll_reports_pending(api):
    device_code = api.post(BEGIN, {}, format='json').json()['device_code']
    response = api.post(POLL, {'device_code': device_code}, format='json')
    assert response.status_code == 200
    assert response.json() == {'status': 'pending'}


@pytest.mark.django_db
def test_poll_returns_the_token_once_approved(api):
    body = api.post(BEGIN, {}, format='json').json()
    user = User.objects.create_user('alice', password='x')
    row = desktop_pairing.find_pending(body['user_code'])
    desktop_pairing.approve(row, user)

    response = api.post(POLL, {'device_code': body['device_code']}, format='json')

    assert response.status_code == 200
    assert response.json()['status'] == 'approved'
    assert response.json()['username'] == 'alice'
    assert len(response.json()['key']) == 40
    assert DesktopPairing.objects.count() == 0


@pytest.mark.django_db
def test_poll_rejects_unknown_and_reused_codes(api):
    assert api.post(POLL, {'device_code': 'nope'}, format='json').status_code == 400
    assert api.post(POLL, {}, format='json').status_code == 400
    assert api.post(POLL, [1], format='json').status_code == 400


@pytest.mark.django_db
def test_poll_reports_denied(api):
    body = api.post(BEGIN, {}, format='json').json()
    desktop_pairing.deny(desktop_pairing.find_pending(body['user_code']))
    response = api.post(POLL, {'device_code': body['device_code']}, format='json')
    assert response.json() == {'status': 'denied'}


@pytest.mark.django_db
def test_verification_url_follows_the_passkey_web_origin(api, settings):
    # conftest's autouse _passkey_settings fixture pins PASSKEY_WEB_ORIGIN
    # equal to OAUTH_ISSUER_URL, which is exactly why the two being confused
    # is invisible by default. Pull them apart.
    settings.PASSKEY_WEB_ORIGIN = 'https://tunnel.example.org'
    settings.OAUTH_ISSUER_URL = 'https://data.etipitaka.com'

    url = api.post(BEGIN, {}, format='json').json()['verification_url']

    assert url.startswith('https://tunnel.example.org/desktop/?code=')
    assert 'data.etipitaka.com' not in url


@pytest.mark.django_db
def test_poll_rejects_a_code_that_was_already_redeemed(api):
    # The test above named "...unknown_and_reused_codes" never actually reuses
    # one; single-use is only proven a layer down in the service tests.
    body = api.post(BEGIN, {}, format='json').json()
    user = User.objects.create_user('alice', password='x')
    desktop_pairing.approve(desktop_pairing.find_pending(body['user_code']), user)

    first = api.post(POLL, {'device_code': body['device_code']}, format='json')
    second = api.post(POLL, {'device_code': body['device_code']}, format='json')

    assert first.status_code == 200
    assert first.json()['status'] == 'approved'
    assert second.status_code == 400
