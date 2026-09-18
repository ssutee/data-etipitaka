import pytest
from django.contrib.auth.models import User
from django.test import Client
from rest_framework.test import APIClient

from user_data import desktop_pairing
from user_data.models import DesktopPairing

BEGIN = '/api/passkeys/desktop/begin/'
POLL = '/api/passkeys/desktop/poll/'
CONFIRM = '/desktop/'
APPROVE = '/desktop/approve/'


@pytest.fixture
def api():
    return APIClient()


@pytest.fixture
def web():
    return Client()


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


@pytest.mark.django_db
def test_confirm_redirects_an_anonymous_visitor_to_login(web):
    response = web.get(CONFIRM + '?code=K7QP-4M2X')
    assert response.status_code == 302
    assert '/login/' in response['Location']


@pytest.mark.django_db
def test_confirm_shows_the_code_and_the_account(web, api):
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')

    response = web.get(CONFIRM + '?code=' + body['user_code'])

    assert response.status_code == 200
    content = response.content.decode()
    assert body['user_code'] in content
    assert 'alice' in content


@pytest.mark.django_db
def test_confirm_is_never_cached(web, api):
    """Both branches of /desktop/ render a page carrying the signed-in
    username, and the first also carries a live pairing code -- a shared
    browser or an intermediary must not replay either to the next visitor.
    Without this, _no_store() could be dropped and the suite stay green.
    """
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')

    confirmation = web.get(CONFIRM + '?code=' + body['user_code'])
    after_decision = web.get(CONFIRM + '?result=approved')

    assert confirmation.status_code == after_decision.status_code == 200
    assert confirmation.headers.get('Cache-Control') == 'no-store'
    assert after_decision.headers.get('Cache-Control') == 'no-store'


@pytest.mark.django_db
def test_approve_redirect_is_never_cached(web, api):
    """The 302 itself, not the page it lands on: a cached redirect would
    replay one visitor's decision result to the next.
    """
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')

    response = web.post(APPROVE, {'code': body['user_code'], 'action': 'approve'})

    assert response.status_code == 302
    assert response.headers.get('Cache-Control') == 'no-store'


@pytest.mark.django_db
def test_confirm_reports_an_unknown_code(web):
    User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')
    response = web.get(CONFIRM + '?code=ZZZZ-9999')
    assert response.status_code == 200
    assert response.context['pairing'] is None


@pytest.mark.django_db
def test_approve_binds_the_pairing_to_the_signed_in_user(web, api):
    body = api.post(BEGIN, {}, format='json').json()
    user = User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')

    response = web.post(APPROVE, {'code': body['user_code'], 'action': 'approve'}, follow=True)

    assert response.status_code == 200
    row = DesktopPairing.objects.get()
    assert row.status == DesktopPairing.APPROVED
    assert row.user == user


@pytest.mark.django_db
def test_approve_with_deny_marks_denied(web, api):
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')

    web.post(APPROVE, {'code': body['user_code'], 'action': 'deny'})

    assert DesktopPairing.objects.get().status == DesktopPairing.DENIED


@pytest.mark.django_db
def test_approve_requires_a_signed_in_user(web, api):
    body = api.post(BEGIN, {}, format='json').json()
    response = web.post(APPROVE, {'code': body['user_code'], 'action': 'approve'})
    assert response.status_code == 302
    assert DesktopPairing.objects.get().status == DesktopPairing.PENDING


@pytest.mark.django_db
def test_approve_ignores_an_unknown_code(web, api):
    """Assert the redirect target, not the rendered context.

    desktop_confirm's ?result= branch hardcodes 'pairing': None for every
    result value, so `response.context['pairing'] is None` after follow=True
    is unconditionally true -- it held just as well when desktop_approve
    reported this unknown code as 'approved'. Where the POST redirects is
    the only thing that tells the outcomes apart.

    A real pending pairing exists alongside, so this also pins down that an
    unknown code decides nothing that does exist.
    """
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    web.login(username='alice', password='secret')

    response = web.post(APPROVE, {'code': 'ZZZZ-9999', 'action': 'approve'}, follow=True)

    assert response.status_code == 200
    assert response.redirect_chain[0][0] == '/desktop/?result=stale'
    assert DesktopPairing.objects.count() == 1  # nothing created
    row = DesktopPairing.objects.get()
    assert row.user_code == body['user_code'].replace('-', '')
    assert row.status == DesktopPairing.PENDING  # nothing altered
    assert row.user is None


@pytest.mark.django_db
def test_approve_requires_a_csrf_token(api):
    # The `web` fixture's plain Client() disables CSRF checks entirely, so
    # without this test @csrf_protect could be deleted and the suite stay
    # green. A forged cross-site POST here would bind a token-granting
    # pairing to the victim's account, so it is worth pinning down.
    strict = Client(enforce_csrf_checks=True)
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    strict.login(username='alice', password='secret')

    response = strict.post(APPROVE, {'code': body['user_code'], 'action': 'approve'})

    assert response.status_code == 403
    assert DesktopPairing.objects.get().status == DesktopPairing.PENDING


@pytest.mark.django_db
def test_approve_accepts_a_valid_csrf_token(api):
    strict = Client(enforce_csrf_checks=True)
    body = api.post(BEGIN, {}, format='json').json()
    User.objects.create_user('alice', password='secret')
    strict.login(username='alice', password='secret')
    strict.get(CONFIRM + '?code=' + body['user_code'])  # mints the CSRF cookie
    token = strict.cookies['csrftoken'].value

    response = strict.post(
        APPROVE, {'code': body['user_code'], 'action': 'approve'},
        HTTP_X_CSRFTOKEN=token, follow=True)

    assert response.status_code == 200
    assert DesktopPairing.objects.get().status == DesktopPairing.APPROVED
