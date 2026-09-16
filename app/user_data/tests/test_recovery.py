import re

import pytest
from django.contrib.auth.forms import _unicode_ci_compare
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from oauth2_provider.models import AccessToken
from rest_framework.authtoken.models import Token

from user_data.recovery import recovery_token_generator

from .conftest import add_passkey, make_oauth_token

pytestmark = pytest.mark.django_db

LINK_RE = re.compile(r'/reset/(?P<uidb64>[^/\s]+)/(?P<token>[^/\s]+)/')


def _request_reset(client, email='alice@example.com'):
    resp = client.post('/password_reset/', {'email': email})
    assert resp.status_code == 302


def _open_link(client):
    """Follow the emailed link; return (uidb64, set-password URL)."""
    match = LINK_RE.search(mail.outbox[-1].body)
    resp = client.get(match.group(0))
    assert resp.status_code == 302
    assert resp['Location'].endswith('/set-password/')
    return match.group('uidb64'), resp['Location']


def test_reset_email_sent_to_passkey_only_user(client, alice, authenticator):
    add_passkey(alice, authenticator)
    alice.set_unusable_password()
    alice.save()
    mail.outbox.clear()
    _request_reset(client)
    assert len(mail.outbox) == 1
    assert LINK_RE.search(mail.outbox[0].body)


def test_reset_email_not_sent_to_inactive_user(client, alice):
    alice.is_active = False
    alice.save()
    _request_reset(client)
    assert mail.outbox == []


def test_token_invalidated_by_new_passkey(alice, authenticator):
    token = recovery_token_generator.make_token(alice)
    assert recovery_token_generator.check_token(alice, token)
    add_passkey(alice, authenticator)
    assert not recovery_token_generator.check_token(alice, token)


def test_token_invalidated_by_password_change(alice):
    """The token must also die on a plain password change, not just a new
    passkey -- _make_hash_value defers to Django's own base implementation
    for this, but that delegation is worth pinning explicitly.
    """
    token = recovery_token_generator.make_token(alice)
    alice.set_password('a-different-password!')
    alice.save()
    assert not recovery_token_generator.check_token(alice, token)


def test_token_invalidated_by_login(alice):
    # A freshly created user (via create_user) has never logged in, so
    # last_login starts out None; any subsequent login updates it and must
    # burn the token just as surely as a password change or a new passkey.
    token = recovery_token_generator.make_token(alice)
    alice.last_login = timezone.now()
    alice.save()
    assert not recovery_token_generator.check_token(alice, token)


def test_token_invalidated_by_email_change(alice):
    token = recovery_token_generator.make_token(alice)
    alice.email = 'someone-else@example.com'
    alice.save()
    assert not recovery_token_generator.check_token(alice, token)


def test_default_token_generator_rejected(alice):
    """A token minted by Django's own default generator (different
    key_salt) must never be accepted by ours -- otherwise a stray
    reference to the stock generator (an old link, a stale client) could
    recover the account without our passkey/email/login extensions ever
    being consulted.
    """
    token = default_token_generator.make_token(alice)
    assert not recovery_token_generator.check_token(alice, token)


def test_unicode_ci_compare_import_still_available():
    """Guard against a Django upgrade silently removing this private
    helper: AccountRecoveryForm.get_users imports it directly, and if it
    is ever renamed or removed this fails loudly here, at collection/run
    time, instead of only surfacing as an ImportError the first time
    someone actually requests a password reset in production.
    """
    assert callable(_unicode_ci_compare)
    assert _unicode_ci_compare('a@Example.com', 'a@example.com')


def test_password_reset_revokes_tokens(client, alice):
    make_oauth_token(alice)
    _request_reset(client)
    _uidb64, set_password_url = _open_link(client)
    resp = client.post(set_password_url, {'new_password1': 'N3w-pass-phrase!',
                                          'new_password2': 'N3w-pass-phrase!'})
    assert resp.status_code == 302
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    alice.refresh_from_db()
    assert alice.check_password('N3w-pass-phrase!')


def test_reset_link_for_passkey_only_user_completes_end_to_end(client, alice, authenticator):
    """A passkey-only account (unusable password) can recover through the
    reset email end to end: the link works, a real password ends up set
    and usable, and it actually authenticates -- not just that an email
    went out.
    """
    add_passkey(alice, authenticator)
    alice.set_unusable_password()
    alice.save()
    mail.outbox.clear()
    _request_reset(client)
    _uidb64, set_password_url = _open_link(client)
    resp = client.post(set_password_url, {'new_password1': 'N3w-pass-phrase!',
                                          'new_password2': 'N3w-pass-phrase!'})
    assert resp.status_code == 302
    alice.refresh_from_db()
    assert alice.has_usable_password()
    assert alice.check_password('N3w-pass-phrase!')
    assert client.login(username=alice.username, password='N3w-pass-phrase!')


def test_confirm_page_context_has_uidb64(client, alice):
    _request_reset(client)
    uidb64, set_password_url = _open_link(client)
    page = client.get(set_password_url)
    assert page.context['validlink'] is True
    assert page.context['uidb64'] == uidb64


def test_reset_redirect_indistinguishable_for_unknown_email(client, alice):
    """No email enumeration: an unknown address must get exactly the same
    redirect as a known one, and only the known one actually sends mail.
    """
    mail.outbox.clear()
    resp_known = client.post('/password_reset/', {'email': alice.email})
    resp_unknown = client.post('/password_reset/', {'email': 'nobody@example.com'})
    assert resp_known.status_code == resp_unknown.status_code == 302
    assert resp_known['Location'] == resp_unknown['Location']
    assert len(mail.outbox) == 1


def test_tampered_uidb64_gives_invalid_link_page_not_500(client):
    uidb64 = urlsafe_base64_encode(b'not-a-real-user')
    resp = client.get('/reset/%s/some-token/' % uidb64)
    assert resp.status_code == 200
    assert resp.context['validlink'] is False


def test_tampered_token_gives_invalid_link_page_not_500(client, alice):
    uidb64 = urlsafe_base64_encode(force_bytes(alice.pk))
    resp = client.get('/reset/%s/garbage-token/' % uidb64)
    assert resp.status_code == 200
    assert resp.context['validlink'] is False


def test_default_generator_token_gives_invalid_link_page(client, alice):
    uidb64 = urlsafe_base64_encode(force_bytes(alice.pk))
    token = default_token_generator.make_token(alice)
    resp = client.get('/reset/%s/%s/' % (uidb64, token))
    assert resp.status_code == 200
    assert resp.context['validlink'] is False
