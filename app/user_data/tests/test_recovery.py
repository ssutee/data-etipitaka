import json
import re

import psycopg
import pytest
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY
from django.contrib.auth.forms import _unicode_ci_compare
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sessions.backends.db import SessionStore
from django.core import mail
from django.core.exceptions import ImproperlyConfigured
from django.db import OperationalError
from django.test import Client, RequestFactory
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from oauth2_provider.models import AccessToken
from rest_framework.authtoken.models import Token

from user_data import passkey_manage as manage
from user_data import recovery
from user_data.recovery import recovery_token_generator

from .conftest import add_passkey, make_oauth_token
from .soft_authenticator import SoftAuthenticator

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


def test_token_dies_when_a_passkey_is_removed(alice, authenticator):
    """test_token_stays_dead_after_passkey_deleted mints its token with
    zero passkeys on the account, so its epoch goes None -> 1 -- that
    proves monotonicity (the token does not come back once dead), but it
    would pass just as well with the delete-side bump in
    passkey_manage.delete_passkey removed entirely, since nothing there
    ever asks the epoch to move a *second* time. This test starts from two
    passkeys (epoch already at 2) and mints the token only then, so the
    only thing that can kill it is the delete itself moving the epoch to
    3 -- pinning bump_passkey_epoch's call from delete_passkey specifically,
    not just the counter's monotonicity.
    """
    passkey_one = add_passkey(alice, authenticator)
    add_passkey(alice, SoftAuthenticator())
    token = recovery_token_generator.make_token(alice)
    assert recovery_token_generator.check_token(alice, token)
    manage.delete_passkey(alice, passkey_one.pk)
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
    the retry path (attempt == _MAX_RECOVERY_ATTEMPTS) instead of a
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
    assert calls['n'] == recovery._MAX_RECOVERY_ATTEMPTS + 1
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


# =============================================================================
# Task 16: recovery passkey endpoints
# =============================================================================


def _begin_recovery(client, uidb64):
    return client.post('/account/recover/passkey/begin/', json.dumps({'uidb64': uidb64}),
                       content_type='application/json')


def _post_json(client, url, body):
    return client.post(url, json.dumps(body), content_type='application/json')


def _recover_with_passkey(client, uidb64, authenticator, **tamper):
    begin = _begin_recovery(client, uidb64)
    assert begin.status_code == 200, begin.content
    body = begin.json()
    return client.post('/account/recover/passkey/finish/', json.dumps({
        'uidb64': uidb64, 'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options'], **tamper)}),
        content_type='application/json')


def _login_session(user):
    """A real, decodable session row carrying the same keys
    django.contrib.auth.login() would set, independent of any Client --
    lets a test create a second, unrelated 'other browser' session for the
    same user. Mirrors test_account_tokens.py's own _login_session helper.
    """
    store = SessionStore()
    store[SESSION_KEY] = str(user.pk)
    store[BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
    store[HASH_SESSION_KEY] = user.get_session_auth_hash()
    store.save()
    return store.session_key


def test_passkey_recovery_signs_in_and_revokes_tokens(client, alice, authenticator):
    alice.set_unusable_password()
    alice.save()
    make_oauth_token(alice)
    _request_reset(client)
    uidb64, set_password_url = _open_link(client)
    resp = _recover_with_passkey(client, uidb64, authenticator)
    assert resp.status_code == 200
    assert resp.json() == {'redirect': '/account/security/'}
    assert client.session['_auth_user_id'] == str(alice.pk)
    # The reset-flow session token must not survive a completed recovery --
    # removing the pop() currently breaks nothing else (the epoch bump
    # already kills the token itself), so this needs its own pin.
    assert recovery.INTERNAL_RESET_SESSION_TOKEN not in client.session
    assert alice.passkeys.count() == 1
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert client.get(set_password_url).context['validlink'] is False  # link spent


def test_passkey_recovery_requires_reset_session(client, alice):
    uidb64 = urlsafe_base64_encode(force_bytes(alice.pk))
    assert _begin_recovery(client, uidb64).status_code == 400


@pytest.mark.parametrize('uidb64', [None, 5, '!!!', 'YWJj'])
def test_passkey_recovery_rejects_bad_uid(client, alice, uidb64):
    _request_reset(client)
    _open_link(client)
    assert _begin_recovery(client, uidb64).status_code == 400


def test_passkey_recovery_rejects_other_users_uid(client, alice, bob):
    _request_reset(client)
    _open_link(client)
    assert _begin_recovery(client, urlsafe_base64_encode(force_bytes(bob.pk))).status_code == 400


def test_passkey_recovery_rejects_inactive_user(client, alice):
    _request_reset(client)
    uidb64, _url = _open_link(client)
    alice.is_active = False
    alice.save()
    assert _begin_recovery(client, uidb64).status_code == 400


def test_passkey_recovery_bad_response_keeps_link(client, alice, authenticator):
    _request_reset(client)
    uidb64, set_password_url = _open_link(client)
    resp = _recover_with_passkey(client, uidb64, authenticator, uv=False)
    assert resp.status_code == 400
    assert client.get(set_password_url).context['validlink'] is True


def test_passkey_recovery_finish_rejects_without_session(client, alice):
    uidb64 = urlsafe_base64_encode(force_bytes(alice.pk))
    resp = client.post('/account/recover/passkey/finish/', json.dumps({'uidb64': uidb64}),
                       content_type='application/json')
    assert resp.status_code == 400


def test_passkey_recovery_requires_csrf():
    csrf_client = Client(enforce_csrf_checks=True)
    resp = csrf_client.post('/account/recover/passkey/begin/', '{}',
                            content_type='application/json')
    assert resp.status_code == 403


# --- crafted-body hardening: these endpoints are anonymous apart from the --
# --- session token, so a malformed body must never turn into a 500 ---------


@pytest.mark.parametrize('body', [[1, 2], 'just a string', 42, True])
def test_passkey_recovery_begin_non_object_json_body_is_400(client, body):
    resp = client.post('/account/recover/passkey/begin/', json.dumps(body),
                       content_type='application/json')
    assert resp.status_code == 400


def test_passkey_recovery_begin_malformed_json_is_400(client):
    resp = client.post('/account/recover/passkey/begin/', 'not json',
                       content_type='application/json')
    assert resp.status_code == 400


@pytest.mark.parametrize('body', [[1, 2], 'just a string', 42, True])
def test_passkey_recovery_finish_non_object_json_body_is_400(client, body):
    resp = client.post('/account/recover/passkey/finish/', json.dumps(body),
                       content_type='application/json')
    assert resp.status_code == 400


def test_passkey_recovery_finish_malformed_json_is_400(client):
    resp = client.post('/account/recover/passkey/finish/', 'not json',
                       content_type='application/json')
    assert resp.status_code == 400


def _nested_body(depth):
    return '{"a":' * depth + '1' + '}' * depth


@pytest.mark.parametrize('url', ['/account/recover/passkey/begin/',
                                 '/account/recover/passkey/finish/'])
def test_passkey_recovery_deeply_nested_json_body_is_400_not_500(client, url):
    # Same nesting-depth reasoning as test_passkey_web.py's own version of
    # this test: json_body() (passkey_web_views.py, shared by every plain-
    # Django passkey endpoint) catches the RecursionError json.loads() has
    # no nesting-depth limit of its own to avoid, turning it into a clean
    # 400 instead of an unhandled 500.
    resp = client.post(url, _nested_body(20000), content_type='application/json')
    assert resp.status_code == 400


@pytest.mark.parametrize('challenge_id', [{'a': 1}, [1, 2], 42, None])
def test_passkey_recovery_finish_crafted_challenge_id_types_are_400(client, alice, challenge_id):
    _request_reset(client)
    uidb64, _url = _open_link(client)
    resp = _post_json(client, '/account/recover/passkey/finish/',
                      {'uidb64': uidb64, 'challenge_id': challenge_id, 'credential': {}})
    assert resp.status_code == 400


@pytest.mark.parametrize('credential', ['not-a-dict', [1, 2], None])
def test_passkey_recovery_finish_crafted_credential_types_are_400(client, alice, credential):
    _request_reset(client)
    uidb64, _url = _open_link(client)
    begin = _begin_recovery(client, uidb64)
    body = begin.json()
    resp = _post_json(client, '/account/recover/passkey/finish/',
                      {'uidb64': uidb64, 'challenge_id': body['challenge_id'],
                       'credential': credential})
    assert resp.status_code == 400


@pytest.mark.parametrize('name', [{'a': 1}, 'x' * 5000])
def test_passkey_recovery_finish_crafted_name_is_sanitized_not_500(client, alice, authenticator,
                                                                    name):
    """clean_name() (Task 1-10) already sanitizes a non-str or over-long
    name rather than rejecting it -- see
    test_signup_finish_crafted_name_is_sanitized_not_500 in
    test_passkey_views.py for the same rule pinned on another ceremony.
    Recovery follows it too, so a crafted name here must still complete the
    recovery (200), unlike a crafted challenge_id/credential (400).
    """
    _request_reset(client)
    uidb64, _url = _open_link(client)
    begin = _begin_recovery(client, uidb64)
    body = begin.json()
    resp = _post_json(client, '/account/recover/passkey/finish/', {
        'uidb64': uidb64, 'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options']), 'name': name})
    assert resp.status_code == 200


@pytest.mark.parametrize('raw_pk', [
    '99999999999999999999999999999999',  # huge: resolves to "no such row", not an error
    '-5',                                 # negative: same
    'not-a-number',                       # non-numeric: ValueError from the pk field itself
])
def test_passkey_recovery_rejects_crafted_uidb64_pk(client, alice, raw_pk):
    """A uidb64 that decodes cleanly from base64 but not to a real primary
    key must 400, never 500, whatever shape the garbage takes.
    """
    _request_reset(client)
    _open_link(client)
    uidb64 = urlsafe_base64_encode(force_bytes(raw_pk))
    assert _begin_recovery(client, uidb64).status_code == 400


# --- session handling: the recovering browser's own session must survive ---


def test_passkey_recovery_keeps_own_session_but_signs_out_other_browser(client, alice,
                                                                        authenticator):
    """finish_recover deletes every OTHER session belonging to `user` inside
    its own transaction. Without keep_session_key, a recovering browser
    that already happens to be signed in as the account being recovered
    would have its own session row deleted out from under this very
    request, and the response's own session save would then fail with a
    400 (SessionInterrupted) once SessionMiddleware finds the row gone.
    Reproduced here by logging the recovering browser itself into the
    account before completing recovery through it: it must still get a 200
    and stay signed in, while a second, unrelated browser session for the
    same user is revoked exactly as before.

    Also pins that the recovering browser's OWN session key actually
    changes -- request.session.cycle_key() is what defeats session
    fixation here, the same reason login_passkey's own login() call cycles
    it, and nothing else in this flow forces a new key (login() itself
    only cycles when SESSION_KEY was *absent*, which is not this test's
    case -- see recover_passkey_finish's own comment). Deleting that one
    cycle_key() call leaves every other assertion in this file passing, so
    without this the fixation defence would be free to regress silently.
    """
    other_key = _login_session(alice)

    # force_login() fires the real user_logged_in signal, which moves
    # last_login -- and the recovery token's hash mixes last_login in (see
    # AccountRecoveryTokenGenerator._make_hash_value), so this must happen
    # BEFORE the reset token is minted below, not after: logging in once a
    # token already exists would immediately burn it, unrelated to
    # anything this test is trying to pin.
    client.force_login(alice)  # the browser doing the recovery is already signed in
    _request_reset(client)
    uidb64, _url = _open_link(client)
    before = client.session.session_key
    resp = _recover_with_passkey(client, uidb64, authenticator)
    assert resp.status_code == 200
    assert resp.json() == {'redirect': '/account/security/'}
    assert client.session['_auth_user_id'] == str(alice.pk)
    assert client.session.session_key != before  # cycle_key() ran -- fixation defeated
    assert not SessionStore.get_model_class().objects.filter(session_key=other_key).exists()


def test_passkey_recovery_ignores_client_supplied_keep_session_key(client, alice, authenticator):
    """keep_session_key must come only from request.session.session_key --
    never from the request body. Name an unrelated session in the JSON
    body's own (otherwise-unused) 'keep_session_key' field; it must still
    be deleted, exactly as if the field had never been sent.
    """
    other_key = _login_session(alice)

    _request_reset(client)
    uidb64, _url = _open_link(client)
    begin = _begin_recovery(client, uidb64)
    assert begin.status_code == 200
    body = begin.json()
    resp = _post_json(client, '/account/recover/passkey/finish/', {
        'uidb64': uidb64, 'challenge_id': body['challenge_id'],
        'credential': authenticator.register(body['options']),
        'keep_session_key': other_key})
    assert resp.status_code == 200
    assert not SessionStore.get_model_class().objects.filter(session_key=other_key).exists()


# --- OperationalError/ImproperlyConfigured must not be silently swallowed --


def test_recover_passkey_finish_does_not_swallow_operational_error(client, alice, authenticator,
                                                                    monkeypatch):
    """finish_recover's own retry loop (passkey_service._run_with_retry) can
    still exhaust every attempt and raise a bare OperationalError -- a rare,
    genuine Postgres availability problem, not anything wrong with this
    request. Deliberately left uncaught: it surfaces as an unhandled 500,
    exactly like every other passkey ceremony view already treats an
    exception outside its own typed set, rather than inventing a bespoke
    JSON error shape just for this endpoint. The reset link itself must
    stay valid either way, so the caller can simply retry.

    Checked here via a FRESH client re-visiting the original emailed link,
    not via the crashed request's own client/cookie: Django's own
    SessionMiddleware.process_response skips saving the session (and so
    skips re-cookieing the client) for any 5xx response, while
    request.session.cycle_key() -- called unconditionally before
    finish_recover, deleting the *old* session row immediately and
    unconditionally -- already ran and committed before the mocked
    finish_recover ever raises. So the crashed request's own client is left
    holding a cookie for a now-deleted row: a session/cookie artifact of a
    5xx response, not a statement about whether the link itself is still
    good.
    """
    _request_reset(client)
    match = LINK_RE.search(mail.outbox[-1].body)
    uidb64, _set_password_url = _open_link(client)
    begin = _begin_recovery(client, uidb64)
    assert begin.status_code == 200
    body = begin.json()

    def _boom(*args, **kwargs):
        raise OperationalError('deadlock detected')

    monkeypatch.setattr(recovery.service, 'finish_recover', _boom)
    with pytest.raises(OperationalError):
        client.post('/account/recover/passkey/finish/', json.dumps({
            'uidb64': uidb64, 'challenge_id': body['challenge_id'],
            'credential': authenticator.register(body['options'])}),
            content_type='application/json')

    assert alice.passkeys.count() == 0
    fresh = Client()
    resp = fresh.get(match.group(0))
    assert resp.status_code == 302
    assert fresh.get(resp['Location']).context['validlink'] is True


def test_recover_passkey_begin_does_not_swallow_improperly_configured(alice, settings):
    """begin_recover's check_session_engine() must be allowed to raise -- a
    misconfigured SESSION_ENGINE is an operator error that has to be fixed,
    not something a client-facing 400 could paper over.

    Exercised against the raw view function via RequestFactory, not the
    Django test client's full middleware stack: changing
    settings.SESSION_ENGINE mid-test would also change how the *next*
    request's own session cookie gets decoded, which would just look like a
    missing reset session (a 400 from _recovering_user) rather than ever
    reaching begin_recover at all.
    """
    session = SessionStore()
    session[recovery.INTERNAL_RESET_SESSION_TOKEN] = recovery_token_generator.make_token(alice)
    session.save()
    request = RequestFactory().post(
        '/account/recover/passkey/begin/',
        json.dumps({'uidb64': urlsafe_base64_encode(force_bytes(alice.pk))}),
        content_type='application/json')
    request.session = session
    request._dont_enforce_csrf_checks = True
    settings.SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
    with pytest.raises(ImproperlyConfigured):
        recovery.recover_passkey_begin(request)


def test_recover_passkey_finish_does_not_swallow_improperly_configured(alice, settings):
    """Same as above for finish_recover: check_session_engine() runs as its
    very first statement, before the challenge is even consumed, so a
    placeholder challenge_id/credential is enough to reach it.
    """
    session = SessionStore()
    session[recovery.INTERNAL_RESET_SESSION_TOKEN] = recovery_token_generator.make_token(alice)
    session.save()
    request = RequestFactory().post(
        '/account/recover/passkey/finish/',
        json.dumps({'uidb64': urlsafe_base64_encode(force_bytes(alice.pk)),
                   'challenge_id': 'x', 'credential': {}}),
        content_type='application/json')
    request.session = session
    request._dont_enforce_csrf_checks = True
    settings.SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
    with pytest.raises(ImproperlyConfigured):
        recovery.recover_passkey_finish(request)


# --- responses must never be cached: both set/rely on a session -------------


def test_passkey_recovery_begin_sets_cache_control_no_store(client, alice):
    """The begin response body carries the challenge, the user's stable
    passkey handle, and every existing credential's descriptor -- exactly
    the kind of response a shared cache/browser must never replay to a
    later, different visitor. Mirrors login_passkey's own no-store header
    (passkey_web_views.py), which reasons about the session cookie a login
    response sets; this endpoint sets no cookie of its own, but the body
    itself is just as sensitive.
    """
    _request_reset(client)
    uidb64, _url = _open_link(client)
    resp = _begin_recovery(client, uidb64)
    assert resp.status_code == 200
    assert resp.headers.get('Cache-Control') == 'no-store'


def test_passkey_recovery_finish_sets_cache_control_no_store(client, alice, authenticator):
    """The finish response sets a session cookie for a full account
    takeover reached by nothing more than possessing the reset email --
    more sensitive than login_passkey's own response, which already earns
    this header for the weaker case of an already-registered device
    logging in.
    """
    _request_reset(client)
    uidb64, _url = _open_link(client)
    resp = _recover_with_passkey(client, uidb64, authenticator)
    assert resp.status_code == 200
    assert resp.headers.get('Cache-Control') == 'no-store'


# --- recovery must bypass the passkey cap: it is how you replace the -------
# --- device that made the account unreachable in the first place -----------


def test_passkey_recovery_bypasses_passkey_cap(client, alice, authenticator, monkeypatch):
    """Complements test_recover_succeeds_at_the_cap (test_passkey_service.py,
    which fills the account to the real default cap and drives
    service.finish_recover directly). This one exercises the same property
    through the actual HTTP endpoints, with the cap monkeypatched down to
    1 so a future change to _store_passkey's own enforce_cap default would
    trip this immediately -- at just one existing passkey -- rather than
    needing 20 dummy rows to notice. Without this, a regression here would
    lock out exactly the users recovery exists for: the ones who lost the
    device holding their only passkey.
    """
    monkeypatch.setattr(recovery.service, 'PASSKEY_MAX_PER_USER', 1)
    add_passkey(alice, SoftAuthenticator())  # fills the (lowered) cap exactly
    assert alice.passkeys.count() == 1

    _request_reset(client)
    uidb64, _url = _open_link(client)
    resp = _recover_with_passkey(client, uidb64, authenticator)
    assert resp.status_code == 200
    assert alice.passkeys.count() == 2


# =============================================================================
# Task 21: recovery confirm page -- "Create a new passkey"
# =============================================================================


def test_confirm_page_offers_passkey_button(client, alice):
    _request_reset(client)
    uidb64, set_password_url = _open_link(client)
    html = client.get(set_password_url).content.decode()
    assert 'id="passkey-recover-button"' in html
    assert 'data-uidb64="%s"' % uidb64 in html
    assert '/static/passkey_recover.js' in html


def test_confirm_page_names_the_account(client, alice):
    """Task 16 review: a victim following an attacker's reset link must be
    able to see whose account they are about to create a passkey for --
    otherwise they could unknowingly bind their authenticator to the
    attacker's account. The username must appear next to the button.
    """
    _request_reset(client)
    _uidb64, set_password_url = _open_link(client)
    html = client.get(set_password_url).content.decode()
    assert alice.username in html


def test_confirm_page_does_not_leak_username_on_invalid_link(client, alice):
    """The same page, reached with a tampered/expired link, must never
    reveal whose account a valid link would have named -- validlink is
    False here, so there is no `user` to name in the first place.
    """
    uidb64 = urlsafe_base64_encode(force_bytes(alice.pk))
    resp = client.get('/reset/%s/garbage-token/' % uidb64)
    assert resp.status_code == 200
    assert resp.context['validlink'] is False
    assert alice.username not in resp.content.decode()


def test_confirm_page_hides_passkey_box_and_keeps_password_form(client, alice):
    """Progressive enhancement: with JS off (or passkeys unsupported), the
    box must render hidden and the ordinary set-password form must still
    be fully present and usable.
    """
    _request_reset(client)
    _uidb64, set_password_url = _open_link(client)
    html = client.get(set_password_url).content.decode()
    assert re.search(r'<div id="passkey-recover"[^>]*\bhidden\b', html)
    assert 'name="new_password1"' in html
    assert 'name="new_password2"' in html
    assert '<form class="form-horizontal" method="post" action="">' in html


def test_confirm_page_escapes_username_and_keeps_it_non_bindable(client):
    """Task 21 review: the username shown next to the passkey-recovery
    button is safe today only because two things stay true together --
    ng-non-bindable on its container, and nothing between here and the
    template ever turning autoescaping off -- with nothing pinning that
    pair. Reaches a payload a normal signup could never submit by writing
    directly via the ORM: create_user() never calls full_clean(), so
    UnicodeUsernameValidator (which SignupSerializer/AccountIdentitySerializer
    enforce) never runs on this write. Mirrors
    test_passkey_name_xss_payload_survives_clean_name_unescaped's own
    technique in test_passkey_pages.py of exercising the render path in
    isolation from what a real request could ever submit.
    """
    payload = 'ev<il<[7*7]>'
    user = recovery.UserModel.objects.create_user(payload, 'evil@example.com', 'password123!')
    _request_reset(client, email=user.email)
    _uidb64, set_password_url = _open_link(client)
    html = client.get(set_password_url).content.decode()

    escaped = 'ev&lt;il&lt;[7*7]&gt;'
    assert payload not in html  # the raw '<' must never reach the body unescaped
    assert escaped in html
    assert '49' not in html  # '{{ 7*7 }}' must never be evaluated

    box_start = html.index('id="passkey-recover"')
    box_open_start = html.rindex('<div', 0, box_start)
    box_open_end = html.index('>', box_start)
    open_tag = html[box_open_start:box_open_end]
    assert 'ng-non-bindable' in open_tag
    username_pos = html.index(escaped, box_open_end)
    box_close_pos = html.index('</div>', box_open_end)
    assert box_open_end < username_pos < box_close_pos  # inside the ng-non-bindable box
