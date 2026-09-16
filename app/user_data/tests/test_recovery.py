import re

import psycopg
import pytest
from django.contrib.auth.forms import _unicode_ci_compare
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.db import OperationalError
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from oauth2_provider.models import AccessToken
from rest_framework.authtoken.models import Token

from user_data import passkey_manage as manage
from user_data import recovery
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


# --- monotonic passkey epoch: the token must not un-die -----------------


def test_token_stays_dead_after_passkey_deleted(alice, authenticator):
    """Reproduces the reversibility bug this guards against: mixing in
    max(passkey pk) is *current state*, not monotonic -- add a passkey
    (correctly kills the token), then delete that same passkey, and
    max(pk) reverts to what it was before, quietly reviving the token for
    the rest of its 3-day window. A monotonic per-user epoch (bumped, and
    never rolled back, on every add AND every delete -- see
    passkey_service.bump_passkey_epoch) closes this: the token must stay
    dead even after the passkey that killed it is gone.
    """
    token = recovery_token_generator.make_token(alice)
    passkey = add_passkey(alice, authenticator)
    assert not recovery_token_generator.check_token(alice, token)
    manage.delete_passkey(alice, passkey.pk)
    assert not recovery_token_generator.check_token(alice, token)


# --- the confirm view must not work for a deactivated user ---------------


def test_reset_link_shows_invalid_page_after_deactivation(client, alice):
    """PasswordResetConfirmView.get_user does not filter is_active on its
    own -- AccountRecoveryConfirmView must add that check itself, matching
    AccountRecoveryForm.get_users (and Task 16's _recovering_user), both of
    which already require an active user. Otherwise a link issued before
    deactivation would still let the holder set a new password (and have
    the account's tokens revoked) on a disabled account.
    """
    _request_reset(client)
    match = LINK_RE.search(mail.outbox[-1].body)
    alice.is_active = False
    alice.save()
    resp = client.get(match.group(0))
    assert resp.status_code == 200
    assert resp.context['validlink'] is False
    alice.refresh_from_db()
    assert alice.check_password('alicepass123')


# --- token revocation after a completed reset must not be all-or-nothing -


def _raise_deadlock():
    cause = psycopg.errors.DeadlockDetected('deadlock detected')
    raise OperationalError('deadlock detected') from cause


def test_token_revocation_retries_then_succeeds_on_deadlock(client, alice, monkeypatch):
    """The password is already set and committed by the time revocation
    runs, so a transient deadlock there must be retried, not left to
    surface as a 500 on an otherwise-successful reset.
    """
    make_oauth_token(alice)
    real_revoke = recovery.revoke_all_tokens
    calls = {'n': 0}

    def _flaky_revoke(user):
        calls['n'] += 1
        if calls['n'] == 1:
            _raise_deadlock()
        return real_revoke(user)

    monkeypatch.setattr(recovery, 'revoke_all_tokens', _flaky_revoke)
    monkeypatch.setattr(recovery.time, 'sleep', lambda *_a, **_kw: None)

    _request_reset(client)
    _uidb64, set_password_url = _open_link(client)
    resp = client.post(set_password_url, {'new_password1': 'N3w-pass-phrase!',
                                          'new_password2': 'N3w-pass-phrase!'})

    assert resp.status_code == 302
    # attempt 1 deadlocks, attempt 2 (the retry) succeeds, then the
    # post-commit sweep runs once more -- see test_recovery's sweep test.
    assert calls['n'] == 3
    assert not AccessToken.objects.filter(user=alice).exists()
    alice.refresh_from_db()
    assert alice.check_password('N3w-pass-phrase!')


def test_token_revocation_gives_up_after_max_deadlock_retries(client, alice, monkeypatch, caplog):
    """Exhausting every retry on a persistent deadlock must also log and
    swallow, not propagate -- the same "the reset already succeeded"
    reasoning as any other persistent revocation failure, just reached via
    the retry path (attempt == _MAX_REVOKE_ATTEMPTS) instead of a
    first-attempt non-retryable error.
    """
    make_oauth_token(alice)
    calls = {'n': 0}

    def _always_deadlocks(_user):
        calls['n'] += 1
        _raise_deadlock()

    monkeypatch.setattr(recovery, 'revoke_all_tokens', _always_deadlocks)
    monkeypatch.setattr(recovery.time, 'sleep', lambda *_a, **_kw: None)

    _request_reset(client)
    _uidb64, set_password_url = _open_link(client)
    resp = client.post(set_password_url, {'new_password1': 'N3w-pass-phrase!',
                                          'new_password2': 'N3w-pass-phrase!'})

    assert resp.status_code == 302
    # the primary revoke's full retry budget, then one more attempt from
    # the post-commit sweep (which is not itself retried).
    assert calls['n'] == recovery._MAX_REVOKE_ATTEMPTS + 1
    alice.refresh_from_db()
    assert alice.check_password('N3w-pass-phrase!')
    assert any(record.name == 'user_data.recovery' and record.levelname == 'ERROR'
              for record in caplog.records)


def test_token_revocation_persistent_failure_is_logged_not_raised(client, alice, monkeypatch, caplog):
    """A non-retryable (or exhausted-retry) revocation failure must be
    logged, not propagated: the password change has already committed and
    the one-time link is already spent, so the caller must still see their
    successful reset complete.
    """
    make_oauth_token(alice)

    def _always_fails(_user):
        raise RuntimeError('token store unavailable')

    monkeypatch.setattr(recovery, 'revoke_all_tokens', _always_fails)

    _request_reset(client)
    _uidb64, set_password_url = _open_link(client)
    resp = client.post(set_password_url, {'new_password1': 'N3w-pass-phrase!',
                                          'new_password2': 'N3w-pass-phrase!'})

    assert resp.status_code == 302
    alice.refresh_from_db()
    assert alice.check_password('N3w-pass-phrase!')
    assert any(record.name == 'user_data.recovery' and record.levelname == 'ERROR'
              for record in caplog.records)


def test_password_reset_sweeps_tokens_minted_during_revocation(client, alice, monkeypatch):
    """DOT validates a Grant or refresh token with a plain, unlocked
    SELECT, so a request racing the primary revoke can still mint a fresh
    token that survives its commit untouched. A post-commit sweep must
    catch that, exactly like passkey_service.finish_recover's own sweep.
    """
    make_oauth_token(alice)
    real_revoke = recovery.revoke_all_tokens
    calls = []

    def _revoke_then_mint(user):
        calls.append(user)
        real_revoke(user)
        if len(calls) == 1:
            # Stand in for a concurrent mint racing the primary revoke.
            make_oauth_token(user)

    monkeypatch.setattr(recovery, 'revoke_all_tokens', _revoke_then_mint)

    _request_reset(client)
    _uidb64, set_password_url = _open_link(client)
    resp = client.post(set_password_url, {'new_password1': 'N3w-pass-phrase!',
                                          'new_password2': 'N3w-pass-phrase!'})

    assert resp.status_code == 302
    assert len(calls) == 2  # the primary revoke, then the post-commit sweep
    assert not AccessToken.objects.filter(user=alice).exists()
