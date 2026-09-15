import json
import secrets
from datetime import timedelta

import cbor2
import psycopg
import pytest
from django.contrib.auth.models import User
from django.core import mail
from django.core.exceptions import ImproperlyConfigured
from django.db import OperationalError, connection
from django.test import Client
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from oauth2_provider.models import AccessToken, Grant, IDToken, RefreshToken
from rest_framework.authtoken.models import Token

from user_data import passkey_challenges as challenges
from user_data import passkey_service as service
from user_data.models import Passkey, PasskeyUserHandle, WebAuthnChallenge
from user_data.passkey_config import android_origin

from .conftest import add_passkey, login_assertion, make_oauth_token
from .soft_authenticator import SoftAuthenticator, b64url, unb64url

pytestmark = pytest.mark.django_db

APPLE_AAGUID = bytes.fromhex('fbfc3007154e4ecc8c0b6e020557d7bd')

# Unicode characters referenced by name below, built with chr() rather than
# embedded literally so the source file stays plain ASCII.
ZWJ = chr(0x200D)          # zero-width joiner
RTL_OVERRIDE = chr(0x202E)  # right-to-left override
ZWSP = chr(0x200B)          # zero-width space
LONE_SURROGATE = chr(0xD800)  # valid JSON/Python str, invalid UTF-8


def _register(user, authenticator, name=None, **tamper):
    challenge_id, options = service.begin_register(user)
    return service.finish_register(user, challenge_id,
                                   authenticator.register(options, **tamper), name=name)


def _safetynet_response(header, payload):
    """Build a fake SafetyNet JWS 'header.payload.sig' response value."""
    parts = [b64url(json.dumps(header).encode()), b64url(json.dumps(payload).encode()), 'sig']
    return '.'.join(parts).encode()


# --- registration -----------------------------------------------------------

def test_begin_register_options(alice):
    challenge_id, options = service.begin_register(alice)
    assert options['rp'] == {'id': 'data.etipitaka.com', 'name': 'E-Tipitaka'}
    assert options['user']['name'] == 'alice'
    assert options['authenticatorSelection']['residentKey'] == 'required'
    assert options['authenticatorSelection']['userVerification'] == 'required'
    assert options['attestation'] == 'none'
    assert options['timeout'] == 300000
    assert options['excludeCredentials'] == []
    assert WebAuthnChallenge.objects.get(pk=challenge_id).purpose == 'register'


def test_user_handle_is_random_and_stable(alice):
    _id1, first = service.begin_register(alice)
    _id2, second = service.begin_register(alice)
    assert first['user']['id'] == second['user']['id']
    assert len(bytes(PasskeyUserHandle.objects.get(user=alice).handle)) == 32


def test_different_users_get_different_handles(alice, bob):
    service.begin_register(alice)
    service.begin_register(bob)
    assert (bytes(PasskeyUserHandle.objects.get(user=alice).handle)
            != bytes(PasskeyUserHandle.objects.get(user=bob).handle))


def test_finish_register_stores_passkey_and_emails(alice, authenticator):
    passkey = _register(alice, authenticator, name='  My phone  ')
    assert passkey.user == alice
    assert passkey.name == 'My phone'
    assert passkey.backed_up is True
    assert passkey.transports == ['internal', 'hybrid']
    assert passkey.sign_count == 0
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ['alice@example.com']
    assert 'My phone' in mail.outbox[0].body
    assert 'https://data.etipitaka.com/account/security/' in mail.outbox[0].body


def test_default_name_comes_from_aaguid(alice):
    assert _register(alice, SoftAuthenticator(aaguid=APPLE_AAGUID)).name == 'Apple Passwords'


def test_default_name_falls_back_to_passkey(alice, authenticator):
    assert _register(alice, authenticator).name == 'Passkey'


def test_exclude_credentials_lists_existing_passkeys(alice, authenticator):
    passkey = _register(alice, authenticator)
    _challenge_id, options = service.begin_register(alice)
    assert [c['id'] for c in options['excludeCredentials']] == [passkey.credential_id]
    assert options['excludeCredentials'][0]['transports'] == ['internal', 'hybrid']


@pytest.mark.parametrize('tamper', [
    {'uv': False}, {'origin': 'https://evil.example'}, {'rp_id': 'evil.example'}])
def test_finish_register_rejects_tampered_response(alice, authenticator, tamper):
    with pytest.raises(service.RegistrationFailed):
        _register(alice, authenticator, **tamper)
    assert not Passkey.objects.exists()
    assert len(mail.outbox) == 0


def test_finish_register_rejects_reused_challenge(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    service.finish_register(alice, challenge_id, authenticator.register(options))
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, SoftAuthenticator().register(options))


def test_finish_register_rejects_challenge_of_other_user(alice, bob, authenticator):
    challenge_id, options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(bob, challenge_id, authenticator.register(options))


def test_finish_register_rejects_duplicate_credential(alice, bob, authenticator):
    _register(alice, authenticator)
    with pytest.raises(service.RegistrationFailed):
        _register(bob, authenticator)
    assert len(mail.outbox) == 1
    assert not bob.passkeys.exists()


@pytest.mark.parametrize('credential', [None, 'x', [], {}])
def test_finish_register_rejects_malformed_credential(alice, credential):
    challenge_id, _options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, credential)


def test_android_origin_accepted_when_configured(alice, authenticator, settings):
    fingerprint = ':'.join(['01'] * 32)
    settings.PASSKEY_ANDROID_CERT_SHA256 = [fingerprint]
    assert _register(alice, authenticator, origin=android_origin(fingerprint)).pk


def test_failed_registration_still_consumes_challenge(alice, authenticator):
    """A failed verify must burn the challenge too, or the ceremony is replayable."""
    challenge_id, options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, authenticator.register(options, uv=False))
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, SoftAuthenticator().register(options))
    assert not Passkey.objects.exists()


@pytest.mark.parametrize('purpose', [WebAuthnChallenge.SIGNUP, WebAuthnChallenge.RECOVER])
def test_finish_register_rejects_challenge_of_wrong_purpose(alice, authenticator, purpose):
    challenge_id, options = service.begin_register(alice)
    WebAuthnChallenge.objects.filter(pk=challenge_id).update(purpose=purpose)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, authenticator.register(options))


def test_finish_register_surfaces_config_errors(alice, authenticator, settings):
    """A broken PASSKEY_ANDROID_CERT_SHA256 is an operator error, not a rejected
    registration -- it must not be swallowed into RegistrationFailed for
    every user trying to register a passkey."""
    settings.PASSKEY_ANDROID_CERT_SHA256 = ['zz:not-hex']
    challenge_id, options = service.begin_register(alice)
    with pytest.raises(ValueError):
        service.finish_register(alice, challenge_id, authenticator.register(options))


# --- passkey cap --------------------------------------------------------------

def _fill_to_cap(user, count=None):
    """Create `count` (default: the cap) dummy Passkey rows directly via the
    ORM -- fast, unlike running `count` real registration ceremonies. Each
    credential_id is real base64url so _descriptors() can still decode it
    when building exclude/allow lists for a later ceremony on this user."""
    n = service.PASSKEY_MAX_PER_USER if count is None else count
    for _i in range(n):
        Passkey.objects.create(user=user, credential_id=b64url(secrets.token_bytes(16)),
                               public_key=b'', name='Cap passkey')


def test_begin_register_refuses_at_the_cap(alice):
    _fill_to_cap(alice)
    with pytest.raises(service.TooManyPasskeys):
        service.begin_register(alice)
    assert not WebAuthnChallenge.objects.filter(purpose=WebAuthnChallenge.REGISTER).exists()


def test_begin_register_allows_one_below_the_cap(alice):
    _fill_to_cap(alice, service.PASSKEY_MAX_PER_USER - 1)
    challenge_id, _options = service.begin_register(alice)
    assert WebAuthnChallenge.objects.filter(pk=challenge_id).exists()


def test_finish_register_refuses_when_cap_reached_between_begin_and_finish(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    _fill_to_cap(alice)  # a concurrent finish filled the account after begin
    with pytest.raises(service.TooManyPasskeys):
        service.finish_register(alice, challenge_id, authenticator.register(options))
    assert alice.passkeys.count() == service.PASSKEY_MAX_PER_USER
    assert len(mail.outbox) == 0


def test_recover_succeeds_at_the_cap(alice, authenticator):
    """An attacker who filled the account with passkeys must not be able to
    block the owner's own recovery."""
    _fill_to_cap(alice)
    challenge_id, options = service.begin_recover(alice)
    passkey = service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert passkey.user == alice
    assert alice.passkeys.count() == service.PASSKEY_MAX_PER_USER + 1


# --- malformed / hostile WebAuthn responses ---------------------------------
# py_webauthn 3.0.0 parses attacker-controlled CBOR without fully guarding
# against structurally-invalid input; these crash with raw TypeError/KeyError/
# IndexError/ValueError/AttributeError instead of its own WebAuthnException
# subclasses.

@pytest.mark.parametrize('public_key', [
    cbor2.dumps(100),           # plain CBOR int -> decode_credential_public_key can't subscript it
    cbor2.dumps([1, 2, 3]),     # CBOR list -> IndexError reading COSE labels
    cbor2.dumps({1: 2}),        # COSE map missing alg -> KeyError
    cbor2.dumps({1: 2, 3: -7}),  # EC2 COSE map missing crv/x/y -> KeyError
], ids=['cbor-int', 'cbor-list', 'map-kty-only', 'map-kty-alg-only'])
def test_finish_register_rejects_crafted_cose_key(alice, authenticator, public_key):
    challenge_id, options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id,
                                authenticator.register(options, public_key=public_key))
    assert not Passkey.objects.exists()
    assert len(mail.outbox) == 0


# --- attestation is requested as "none" and must never be trusted ----------
# _neutralize_attestation replaces whatever attStmt/fmt an authenticator
# sends with an empty 'none' one before verification, keeping only authData.
# So a junk attestation statement with an otherwise-valid authData/key must
# no longer block registration -- and, crucially, must never reach
# py_webauthn's packed/tpm/android-key/apple/android-safetynet/fido-u2f
# parsers, which is what let a crafted android-safetynet response raise a
# raw AttributeError before this fix.

def test_finish_register_ignores_packed_junk_attestation_with_valid_auth_data(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    att_stmt = {'alg': -7, 'sig': secrets.token_bytes(64), 'x5c': [secrets.token_bytes(50)]}
    passkey = service.finish_register(
        alice, challenge_id, authenticator.register(options, fmt='packed', att_stmt=att_stmt))
    assert passkey.pk


def test_finish_register_ignores_tpm_junk_attestation_with_valid_auth_data(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    att_stmt = {'ver': '2.0', 'alg': -7, 'x5c': [secrets.token_bytes(50)],
                'sig': secrets.token_bytes(64), 'certInfo': secrets.token_bytes(50),
                'pubArea': secrets.token_bytes(50)}
    passkey = service.finish_register(
        alice, challenge_id, authenticator.register(options, fmt='tpm', att_stmt=att_stmt))
    assert passkey.pk


@pytest.mark.parametrize('fmt,att_stmt', [
    ('android-safetynet', {'ver': '1', 'response': 12345}),
    ('android-safetynet', {'ver': '1', 'response': [1, 2, 3]}),
    ('android-safetynet', {'ver': '1', 'response': _safetynet_response([1], {'nonce': 'x'})}),
    ('android-safetynet', {'ver': '1', 'response': _safetynet_response({'alg': 'RS256'}, 's')}),
    ('fido-u2f', {'sig': secrets.token_bytes(64), 'x5c': [secrets.token_bytes(50)]}),
], ids=['response-int', 'response-list', 'header-not-a-map', 'payload-not-a-map', 'fido-u2f-junk'])
def test_finish_register_ignores_attestation_shapes_that_used_to_crash(alice, authenticator,
                                                                        fmt, att_stmt):
    """Before _neutralize_attestation, each of these reached py_webauthn's
    android-safetynet or fido-u2f parser and raised a raw AttributeError or
    ValueError. Attestation is now discarded before verification, so a junk
    statement with a valid authData/key must not block registration."""
    challenge_id, options = service.begin_register(alice)
    passkey = service.finish_register(
        alice, challenge_id, authenticator.register(options, fmt=fmt, att_stmt=att_stmt))
    assert passkey.pk


def test_finish_register_rejects_packed_attestation_when_key_is_bad(alice, authenticator):
    """Ignoring attestation must not extend to ignoring a bad authData/key:
    it only means the attStmt itself is no longer trusted."""
    challenge_id, options = service.begin_register(alice)
    att_stmt = {'alg': -7, 'sig': secrets.token_bytes(64), 'x5c': [secrets.token_bytes(50)]}
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(
            alice, challenge_id,
            authenticator.register(options, fmt='packed', att_stmt=att_stmt,
                                   public_key=cbor2.dumps(100)))
    assert not Passkey.objects.exists()


def test_finish_register_rejects_attestation_object_that_is_not_a_map(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    credential = authenticator.register(options)
    credential['response']['attestationObject'] = b64url(cbor2.dumps([1, 2, 3]))
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, credential)
    assert not Passkey.objects.exists()


def test_finish_register_rejects_attestation_object_missing_auth_data(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    credential = authenticator.register(options)
    credential['response']['attestationObject'] = b64url(cbor2.dumps({'fmt': 'none', 'attStmt': {}}))
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, credential)


def test_finish_register_rejects_attestation_object_with_non_bytes_auth_data(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    credential = authenticator.register(options)
    credential['response']['attestationObject'] = b64url(
        cbor2.dumps({'fmt': 'none', 'attStmt': {}, 'authData': 'not-bytes'}))
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, credential)


def test_finish_register_rejects_attestation_object_with_bad_cbor(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    credential = authenticator.register(options)
    credential['response']['attestationObject'] = b64url(b'')  # premature EOF for cbor2
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, credential)


def test_finish_register_rejects_attestation_object_with_bad_base64(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    credential = authenticator.register(options)
    credential['response']['attestationObject'] = 'not valid base64url!!'
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, credential)


# --- public keys that verify but are not usable cryptographically ----------
# These pass py_webauthn's structural checks with fmt "none" (nothing there
# verifies the key is a real point), then break the first login attempt.

@pytest.mark.parametrize('public_key', [
    cbor2.dumps(4),  # single 0x04 byte: read as a legacy "uncompressed EC point"
                     # marker with empty x/y coordinates
    cbor2.dumps({1: 2, 3: -7, -1: 1,
                 -2: secrets.token_bytes(32), -3: secrets.token_bytes(32)}),  # off-curve point
    cbor2.dumps({1: 2, 3: -7, -1: 1, -2: 12345, -3: 67890}),  # int x/y instead of bytes
], ids=['uncompressed-point-marker', 'off-curve-point', 'int-coordinates'])
def test_finish_register_rejects_key_that_cannot_be_decoded(alice, authenticator, public_key):
    challenge_id, options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id,
                                authenticator.register(options, public_key=public_key))
    assert not Passkey.objects.exists()
    assert len(mail.outbox) == 0


# --- storage-layer hardening -------------------------------------------------

def test_finish_register_rejects_oversized_credential_id(alice, authenticator):
    authenticator.credential_id = secrets.token_bytes(1024)
    challenge_id, options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, authenticator.register(options))
    assert not Passkey.objects.exists()


def test_finish_register_accepts_credential_id_at_max_length(alice, authenticator):
    authenticator.credential_id = secrets.token_bytes(1023)
    assert _register(alice, authenticator).pk


def test_finish_register_defaults_transports_when_not_a_list(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    credential = authenticator.register(options)
    credential['response']['transports'] = 5  # not iterable -- must not crash
    passkey = service.finish_register(alice, challenge_id, credential)
    assert passkey.transports == []


# --- email delivery is best-effort ------------------------------------------

def test_finish_register_keeps_passkey_when_email_fails(alice, authenticator, monkeypatch, caplog):
    def _boom(*args, **kwargs):
        raise RuntimeError('smtp is down')
    monkeypatch.setattr(service, 'send_mail', _boom)
    passkey = _register(alice, authenticator)
    assert Passkey.objects.filter(pk=passkey.pk).exists()
    assert any(record.name == 'user_data.passkey_service' and record.levelname == 'ERROR'
              for record in caplog.records)


def test_finish_register_keeps_passkey_when_email_render_fails(alice, authenticator, monkeypatch,
                                                                caplog):
    """A broken email template must not turn a stored passkey into a 500 --
    render_to_string can raise just as easily as send_mail, and both run
    after the passkey is already committed."""
    def _boom(*args, **kwargs):
        raise RuntimeError('template is broken')
    monkeypatch.setattr(service, 'render_to_string', _boom)
    passkey = _register(alice, authenticator)
    assert Passkey.objects.filter(pk=passkey.pk).exists()
    assert any(record.name == 'user_data.passkey_service' and record.levelname == 'ERROR'
              for record in caplog.records)


def test_finish_register_sends_no_email_for_user_without_email(authenticator):
    user = User.objects.create_user('carol', '', 'carolpass123')
    passkey = _register(user, authenticator)
    assert passkey.pk
    assert len(mail.outbox) == 0


# --- clean_name hardening ----------------------------------------------------

@pytest.mark.parametrize('raw,expected', [
    ('Ali\x00ce', 'Alice'),                    # NUL (Cc)
    ('Ali\ud800ce', 'Alice'),                  # lone surrogate (Cs)
    ('Ali' + RTL_OVERRIDE + 'ce', 'Alice'),    # RTL override (Cf)
    ('Ali' + ZWJ + 'ce', 'Ali' + ZWJ + 'ce'),  # ZWJ (Cf) is explicitly kept
], ids=['nul', 'lone-surrogate', 'bidi-override', 'zwj-kept'])
def test_clean_name_strips_disallowed_categories(raw, expected):
    assert service.clean_name(raw) == expected


def test_clean_name_strips_newline_injection():
    cleaned = service.clean_name('My phone\nX-Injected: header')
    assert '\n' not in cleaned
    assert '\r' not in cleaned


def test_clean_name_collapses_control_whitespace_before_filtering():
    """Collapsing whitespace before filtering categories means a tab or
    newline used as a word separator leaves one space, not a merged word."""
    assert service.clean_name('My\nphone') == 'My phone'
    assert service.clean_name('My\tphone') == 'My phone'


def test_clean_name_final_collapse_removes_gap_left_by_filtered_char():
    # ZWSP (Cf) sits between two literal spaces; deleting it must not leave
    # a double space behind -- this is why collapsing runs a second time.
    assert service.clean_name('Work ' + ZWSP + ' laptop') == 'Work laptop'


def test_clean_name_truncates_then_strips_trailing_space_at_cut():
    assert service.clean_name('a' * 99 + ' b') == 'a' * 99


def test_clean_name_collapses_internal_whitespace():
    assert service.clean_name('  My   phone  ') == 'My phone'


def test_clean_name_whitespace_only_returns_empty():
    assert service.clean_name('   ') == ''


def test_clean_name_only_zwj_returns_empty():
    assert service.clean_name(ZWJ + ZWJ) == ''


@pytest.mark.parametrize('value', [123, {'a': 1}, ['x']])
def test_clean_name_non_string_returns_empty(value):
    assert service.clean_name(value) == ''


# --- login --------------------------------------------------------------

def test_begin_login_options():
    challenge_id, options = service.begin_login()
    assert options['rpId'] == 'data.etipitaka.com'
    assert options['allowCredentials'] == []
    assert options['userVerification'] == 'required'
    assert WebAuthnChallenge.objects.get(pk=challenge_id).purpose == 'login'


def test_finish_login_returns_user_and_records_use(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    assert service.finish_login(*login_assertion(authenticator)) == alice
    passkey.refresh_from_db()
    assert passkey.sign_count == 1
    assert passkey.backed_up is True
    assert passkey.last_used_at is not None
    alice.refresh_from_db()
    assert alice.last_login is not None


def test_synced_passkey_with_zero_counter_logs_in_repeatedly(alice, authenticator):
    add_passkey(alice, authenticator)
    for _i in range(2):
        assert service.finish_login(*login_assertion(authenticator, sign_count=0)) == alice


@pytest.mark.parametrize('tamper', [
    {'uv': False}, {'origin': 'https://evil.example'}, {'rp_id': 'evil.example'},
    {'corrupt_signature': True}, {'omit_user_handle': True}, {'user_handle': b'x' * 32}])
def test_finish_login_rejects_tampered_assertion(alice, authenticator, tamper):
    add_passkey(alice, authenticator)
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(*login_assertion(authenticator, **tamper))


def test_finish_login_rejects_counter_regression(alice, authenticator):
    add_passkey(alice, authenticator)
    service.finish_login(*login_assertion(authenticator, sign_count=5))
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(*login_assertion(authenticator, sign_count=3))


def test_finish_login_rejects_unknown_credential(alice, authenticator):
    add_passkey(alice, authenticator)
    stranger = SoftAuthenticator()
    stranger.user_handle = b'z' * 32
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(*login_assertion(stranger))


def test_finish_login_rejects_reused_challenge(alice, authenticator):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    service.finish_login(challenge_id, credential)
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


def test_register_challenge_cannot_finish_login(alice, authenticator):
    add_passkey(alice, authenticator)
    register_id, _register_options = service.begin_register(alice)
    _login_id, options = service.begin_login()
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(register_id, authenticator.assert_(options))


@pytest.mark.parametrize('credential', [None, 'x', [], {}])
def test_finish_login_rejects_malformed_credential(credential):
    challenge_id, _options = service.begin_login()
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


def test_finish_login_inactive_user(alice, authenticator):
    add_passkey(alice, authenticator)
    alice.is_active = False
    alice.save()
    with pytest.raises(service.InactiveUser):
        service.finish_login(*login_assertion(authenticator))


def test_finish_login_surfaces_config_errors_and_keeps_challenge(settings):
    """Same lesson as registration: a broken PASSKEY_ANDROID_CERT_SHA256 is
    an operator error, not a rejected login -- and reading config before
    consuming the challenge means the challenge survives to be retried once
    the setting is fixed, instead of being burned on an error that had
    nothing to do with the assertion."""
    settings.PASSKEY_ANDROID_CERT_SHA256 = ['zz:not-hex']
    challenge_id, _options = service.begin_login()
    with pytest.raises(ValueError):
        service.finish_login(challenge_id, {})
    assert WebAuthnChallenge.objects.filter(pk=challenge_id).exists()


def test_finish_login_failed_verify_still_consumes_challenge(alice, authenticator):
    """A failed verify must burn the challenge too, or the ceremony is
    replayable -- even a subsequent genuinely-signed assertion against the
    same challenge id must not be accepted afterwards."""
    add_passkey(alice, authenticator)
    challenge_id, options = service.begin_login()
    bad_credential = authenticator.assert_(options, corrupt_signature=True)
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, bad_credential)
    good_credential = authenticator.assert_(options)
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, good_credential)


def test_finish_login_rejects_challenge_of_wrong_purpose_when_user_matches(alice, authenticator):
    """The purpose column alone must gate a login challenge. The passkey is
    genuinely registered and the assertion uses the authenticator's real
    (matching) user handle, so everything else about this attempt would
    succeed -- isolating the purpose filter from the separate user filter
    that test_register_challenge_cannot_finish_login also exercises (a
    register challenge belongs to a user, a second reason it fails). A
    signup challenge is, like a login challenge, issued with user=None."""
    add_passkey(alice, authenticator)
    row = challenges.create(WebAuthnChallenge.SIGNUP)
    options = {'challenge': b64url(bytes(row.challenge)), 'rpId': 'data.etipitaka.com'}
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(row.id, authenticator.assert_(options))


# --- crafted / hostile login assertions --------------------------------
# Like registration, py_webauthn 3.0.0 parses attacker-controlled CBOR/JSON
# for an assertion without fully guarding against structurally-invalid
# input, so a crafted response can raise a raw ValueError/KeyError/
# TypeError/IndexError/AttributeError instead of one of its own
# WebAuthnException subclasses. finish_login must turn every one of these
# into InvalidCredentials, never let the raw exception escape.

def test_finish_login_rejects_non_dict_response(alice, authenticator):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    credential['response'] = 'not-a-dict'
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


@pytest.mark.parametrize('field,value', [
    ('clientDataJSON', 12345),
    ('clientDataJSON', 'not valid base64!!'),
    ('authenticatorData', 12345),
    ('authenticatorData', 'not valid base64!!'),
    ('signature', [1, 2, 3]),
    ('signature', 'not valid base64!!'),
], ids=['cdj-nonstring', 'cdj-badb64', 'authdata-nonstring', 'authdata-badb64',
        'sig-nonstring', 'sig-badb64'])
def test_finish_login_rejects_crafted_response_fields(alice, authenticator, field, value):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    credential['response'][field] = value
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


def test_finish_login_rejects_non_string_user_handle(alice, authenticator):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    credential['response']['userHandle'] = 12345
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


def test_finish_login_rejects_raw_id_mismatch(alice, authenticator):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    credential['rawId'] = b64url(secrets.token_bytes(32))
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


def test_finish_login_rejects_id_mismatch_with_genuine_raw_id(alice, authenticator):
    """The id/rawId equivalence check must catch either direction: a
    genuine rawId paired with a forged id, not just a forged rawId."""
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    credential['id'] = b64url(secrets.token_bytes(32))
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


def test_finish_login_rejects_truncated_authenticator_data(alice, authenticator):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    credential['response']['authenticatorData'] = b64url(b'\x00' * 10)
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


@pytest.mark.parametrize('public_key', [b'\x04', secrets.token_bytes(20)],
                         ids=['single-byte', 'random-bytes'])
def test_finish_login_rejects_corrupt_stored_public_key(alice, authenticator, public_key):
    """A legacy/corrupt public_key row must end as InvalidCredentials, not a 500."""
    passkey = add_passkey(alice, authenticator)
    Passkey.objects.filter(pk=passkey.pk).update(public_key=public_key)
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(*login_assertion(authenticator))


def test_finish_login_rejects_very_long_credential_id(alice, authenticator):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    credential['id'] = 'A' * 5000
    credential['rawId'] = 'A' * 5000
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


# --- usage recording is race-safe -------------------------------------------
# The sign_count/backed_up/last_used_at update, and the last_login update,
# go through a conditional queryset .update() rather than
# instance.save(update_fields=...): a concurrent request must not be able
# to lower the counter, and a row deleted between verification and the
# update must raise this module's own InvalidCredentials, not the raw
# DatabaseError save(update_fields=...) would raise for a zero-row update.

def test_finish_login_race_deleted_passkey_raises_invalid_credentials(alice, authenticator,
                                                                       monkeypatch):
    passkey = add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    real_verify = service.verify_authentication_response

    def _verify_then_delete(**kwargs):
        result = real_verify(**kwargs)
        Passkey.objects.filter(pk=passkey.pk).delete()
        return result

    monkeypatch.setattr(service, 'verify_authentication_response', _verify_then_delete)
    with pytest.raises(service.InvalidCredentials):
        service.finish_login(challenge_id, credential)


def test_finish_login_race_does_not_lower_counter(alice, authenticator, monkeypatch):
    passkey = add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator, sign_count=5)
    real_verify = service.verify_authentication_response

    def _verify_then_bump(**kwargs):
        result = real_verify(**kwargs)
        Passkey.objects.filter(pk=passkey.pk).update(sign_count=100)
        return result

    monkeypatch.setattr(service, 'verify_authentication_response', _verify_then_bump)
    assert service.finish_login(challenge_id, credential) == alice
    passkey.refresh_from_db()
    assert passkey.sign_count == 100


def test_finish_login_sets_last_login(alice, authenticator):
    add_passkey(alice, authenticator)
    service.finish_login(*login_assertion(authenticator))
    alice.refresh_from_db()
    assert alice.last_login is not None


# --- clone-detection logging -------------------------------------------------

def test_finish_login_logs_counter_regression_at_warning(alice, authenticator, caplog):
    add_passkey(alice, authenticator)
    service.finish_login(*login_assertion(authenticator, sign_count=5))
    with caplog.at_level('WARNING', logger='user_data.passkey_service'):
        with pytest.raises(service.InvalidCredentials):
            service.finish_login(*login_assertion(authenticator, sign_count=3))
    assert any(r.levelname == 'WARNING' for r in caplog.records)


def test_finish_login_forged_counter_regression_does_not_log_warning(alice, authenticator,
                                                                      caplog):
    """py_webauthn checks the counter before the signature, so a forged
    assertion -- a different key, the victim's real credential id and user
    handle, and a low counter -- trips the exact same counter-regression
    message the genuine case does, without its signature ever being
    genuine. It must still be rejected, but only ever logged at INFO."""
    passkey = add_passkey(alice, authenticator)
    service.finish_login(*login_assertion(authenticator))  # bumps sign_count above 0
    passkey.refresh_from_db()
    assert passkey.sign_count > 0

    forger = SoftAuthenticator()  # a different private key than alice's real passkey
    forger.credential_id = unb64url(passkey.credential_id)
    forger.user_handle = bytes(PasskeyUserHandle.objects.get(user=alice).handle)
    challenge_id, options = service.begin_login()
    forged_credential = forger.assert_(options, sign_count=0)

    with caplog.at_level('INFO', logger='user_data.passkey_service'):
        with pytest.raises(service.InvalidCredentials):
            service.finish_login(challenge_id, forged_credential)
    assert not any(r.levelname == 'WARNING' for r in caplog.records)
    assert any(r.levelname == 'INFO' for r in caplog.records)


def test_finish_login_bad_signature_does_not_log_warning(alice, authenticator, caplog):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator, corrupt_signature=True)
    with caplog.at_level('INFO', logger='user_data.passkey_service'):
        with pytest.raises(service.InvalidCredentials):
            service.finish_login(challenge_id, credential)
    assert not any(r.levelname == 'WARNING' for r in caplog.records)
    assert any(r.levelname == 'INFO' for r in caplog.records)


# --- check_password ----------------------------------------------------
# Also used, unmodified, by passkey_manage.remove_password in a later task.

def test_check_password_accepts_correct_password(alice):
    assert service.check_password(alice, 'alicepass123') is True


def test_check_password_rejects_wrong_password(alice):
    assert service.check_password(alice, 'wrong') is False


def test_check_password_rejects_for_passkey_only_user(alice):
    alice.set_unusable_password()
    alice.save()
    assert service.check_password(alice, 'alicepass123') is False


@pytest.mark.parametrize('password', [
    LONE_SURROGATE, 12345, None, '', ['alicepass123'], {'a': 1}, b'alicepass123'],
    ids=['lone-surrogate', 'int', 'none', 'empty', 'list', 'dict', 'bytes'])
def test_check_password_rejects_bad_input(alice, password):
    assert service.check_password(alice, password) is False


# --- step-up --------------------------------------------------------------

def test_step_up_with_password(alice):
    service.verify_step_up(alice, password='alicepass123')
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, password='wrong')


def test_step_up_password_refused_for_passkey_only_user(alice):
    alice.set_unusable_password()
    alice.save()
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, password='alicepass123')


def test_step_up_rejects_lone_surrogate_password(alice):
    """A lone UTF-16 surrogate is valid JSON and decodes to a valid Python
    str, but str.encode('utf-8') on it raises deep inside the password
    hasher -- must end as StepUpFailed, never an unhandled 500."""
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, password=LONE_SURROGATE)


@pytest.mark.parametrize('password', [12345, ['x'], {'a': 1}])
def test_step_up_rejects_non_string_password(alice, password):
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, password=password)


def test_step_up_rejects_empty_password(alice):
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, password='')


def test_step_up_wrong_password_takes_precedence_over_valid_assertion(alice, authenticator):
    """password is checked first; a wrong one is not a chance to fall back
    to a valid assertion also supplied in the same call."""
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, password='wrong',
                               assertion={'challenge_id': challenge_id, 'credential': credential})


def test_step_up_with_own_passkey(alice, authenticator):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    service.verify_step_up(alice, assertion={'challenge_id': challenge_id,
                                             'credential': credential})


def test_step_up_rejects_other_users_passkey(alice, bob, authenticator):
    passkey = add_passkey(bob, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, assertion={'challenge_id': challenge_id,
                                                 'credential': credential})
    passkey.refresh_from_db()
    assert passkey.sign_count == 0
    assert passkey.last_used_at is None


@pytest.mark.parametrize('assertion', [None, 'x', {}, {'challenge_id': 'nope', 'credential': {}}])
def test_step_up_rejects_missing_or_bad_assertion(alice, assertion):
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, assertion=assertion)


# --- signup -----------------------------------------------------------------

def _signup(authenticator, username='newbie', email='n@example.com', **tamper):
    challenge_id, options = service.begin_signup(username, email)
    return service.finish_signup(challenge_id, authenticator.register(options, **tamper),
                                 name='Phone')


def test_begin_signup_creates_no_user():
    challenge_id, options = service.begin_signup('newbie', 'n@example.com')
    assert options['user']['name'] == 'newbie'
    assert not User.objects.filter(username='newbie').exists()
    assert WebAuthnChallenge.objects.get(pk=challenge_id).payload['email'] == 'n@example.com'


def test_begin_signup_rejects_invalid_identity(alice):
    with pytest.raises(service.SignupInvalid) as exc:
        service.begin_signup('alice', 'not-an-email')
    assert set(exc.value.errors) == {'username', 'email'}
    assert all(isinstance(m, str) for msgs in exc.value.errors.values() for m in msgs)


@pytest.mark.parametrize('bad_email', [123, {'a': 1}, ['x'], None],
                         ids=['int', 'dict', 'list', 'none'])
def test_begin_signup_rejects_non_string_email(bad_email):
    """A non-string email must never crash begin_signup: DRF's CharField
    only coerces str/int/float, so an int is stringified and then fails
    EmailField's format validator; a dict/list fails the type check
    outright and None fails the required-field check. All three end as
    SignupInvalid, never a raw exception."""
    with pytest.raises(service.SignupInvalid) as exc:
        service.begin_signup('newbie', bad_email)
    assert 'email' in exc.value.errors


@pytest.mark.parametrize('bad_username', [{'a': 1}, ['x'], None],
                         ids=['dict', 'list', 'none'])
def test_begin_signup_rejects_non_string_username(bad_username):
    with pytest.raises(service.SignupInvalid) as exc:
        service.begin_signup(bad_username, 'n@example.com')
    assert 'username' in exc.value.errors


def test_begin_signup_coerces_numeric_username():
    """Unlike dict/list/None, an int username is not rejected: DRF's
    CharField coerces basic numerics to their string form (the same
    leniency the password-signup endpoint already had). It must not
    crash, and the resulting options carry the stringified value."""
    _challenge_id, options = service.begin_signup(12345, 'n@example.com')
    assert options['user']['name'] == '12345'


def test_finish_signup_creates_inactive_passkey_only_user(authenticator):
    user = _signup(authenticator)
    assert user.is_active is False
    assert user.has_usable_password() is False
    assert user.email == 'n@example.com'
    assert user.passkeys.get().name == 'Phone'
    assert bytes(PasskeyUserHandle.objects.get(user=user).handle) == authenticator.user_handle
    assert mail.outbox == []  # the view sends the verification email


def test_signup_user_can_log_in_after_activation(authenticator):
    user = _signup(authenticator)
    with pytest.raises(service.InactiveUser):
        service.finish_login(*login_assertion(authenticator))
    user.is_active = True
    user.save()
    assert service.finish_login(*login_assertion(authenticator)) == user


def test_finish_signup_rejects_username_taken_since_begin(authenticator):
    challenge_id, options = service.begin_signup('newbie', 'n@example.com')
    User.objects.create_user('newbie', 'other@example.com', 'pw12345678')
    with pytest.raises(service.SignupInvalid) as exc:
        service.finish_signup(challenge_id, authenticator.register(options))
    assert 'username' in exc.value.errors
    assert Passkey.objects.count() == 0


def test_finish_signup_integrity_race_reports_username(authenticator, monkeypatch):
    challenge_id, options = service.begin_signup('newbie', 'n@example.com')
    User.objects.create_user('newbie', 'other@example.com', 'pw12345678')

    class AlwaysValid:
        errors = {}

        def __init__(self, data):
            pass

        def is_valid(self):
            return True

    monkeypatch.setattr(service, 'AccountIdentitySerializer', AlwaysValid)
    with pytest.raises(service.SignupInvalid) as exc:
        service.finish_signup(challenge_id, authenticator.register(options))
    assert 'username' in exc.value.errors
    assert Passkey.objects.count() == 0
    assert not PasskeyUserHandle.objects.filter(user__username='newbie').exists()


def test_begin_signup_rejects_email_too_long():
    """DRF's EmailField has no max_length of its own and Django's
    EmailValidator allows up to 320 characters, but User.email is a
    varchar(254) -- without an explicit max_length this email sails past
    validation and only blows up as a raw DataError once finish_signup
    tries to save the row, with the challenge already burnt."""
    with pytest.raises(service.SignupInvalid) as exc:
        service.begin_signup('newbie', 'a' * 250 + '@example.com')
    assert 'email' in exc.value.errors


def test_finish_signup_rechecks_email_taken_since_begin(authenticator):
    """The username/email re-check in finish_signup earns its keep on
    email, not username: User.email carries no DB uniqueness constraint,
    so nothing but this re-validation would catch a same-email signup
    that raced in between begin_signup and finish_signup."""
    challenge_id, options = service.begin_signup('newbie', 'n@example.com')
    User.objects.create_user('other', 'n@example.com', 'pw12345678')
    with pytest.raises(service.SignupInvalid) as exc:
        service.finish_signup(challenge_id, authenticator.register(options))
    assert 'email' in exc.value.errors
    assert not User.objects.filter(username='newbie').exists()
    assert Passkey.objects.count() == 0
    assert not PasskeyUserHandle.objects.filter(user__username='newbie').exists()


def test_finish_signup_rejects_bad_response(authenticator):
    with pytest.raises(service.RegistrationFailed):
        _signup(authenticator, uv=False)
    assert not User.objects.filter(username='newbie').exists()


def test_finish_signup_duplicate_credential_rolls_back_user(alice, authenticator):
    add_passkey(alice, authenticator)
    with pytest.raises(service.RegistrationFailed):
        _signup(authenticator)
    assert not User.objects.filter(username='newbie').exists()


@pytest.mark.parametrize('credential', [None, 'x', [], {}])
def test_finish_signup_rejects_malformed_credential(credential):
    challenge_id, _options = service.begin_signup('newbie', 'n@example.com')
    with pytest.raises(service.RegistrationFailed):
        service.finish_signup(challenge_id, credential)
    assert not User.objects.filter(username='newbie').exists()


@pytest.mark.parametrize('purpose', [WebAuthnChallenge.LOGIN, WebAuthnChallenge.REGISTER])
def test_finish_signup_rejects_challenge_of_wrong_purpose(authenticator, purpose):
    challenge_id, options = service.begin_signup('newbie', 'n@example.com')
    WebAuthnChallenge.objects.filter(pk=challenge_id).update(purpose=purpose)
    with pytest.raises(service.RegistrationFailed):
        service.finish_signup(challenge_id, authenticator.register(options), name='Phone')
    assert not User.objects.filter(username='newbie').exists()


def test_finish_signup_rejects_reused_challenge(authenticator):
    challenge_id, options = service.begin_signup('newbie', 'n@example.com')
    service.finish_signup(challenge_id, authenticator.register(options), name='Phone')
    with pytest.raises(service.RegistrationFailed):
        service.finish_signup(challenge_id, SoftAuthenticator().register(options))
    assert User.objects.filter(username='newbie').count() == 1


# --- recovery ---------------------------------------------------------------

def test_recover_adds_passkey_and_revokes_tokens(alice, bob, authenticator):
    make_oauth_token(alice)
    make_oauth_token(bob)
    challenge_id, options = service.begin_recover(alice)
    passkey = service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert passkey.user == alice
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert len(mail.outbox) == 1
    # bob's own tokens must survive an unrelated user's recovery
    assert Token.objects.filter(user=bob).exists()
    assert AccessToken.objects.filter(user=bob).exists()


def test_register_challenge_cannot_finish_recovery(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert Token.objects.filter(user=alice).exists()
    assert len(mail.outbox) == 0


def test_recover_challenge_cannot_finish_register(alice, authenticator):
    challenge_id, options = service.begin_recover(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, authenticator.register(options))
    assert Passkey.objects.count() == 0


def test_finish_recover_rejects_bad_response(alice, authenticator):
    """A tampered/failed recovery response must leave everything alone:
    tokens intact, no email, no passkey stored. The challenge is still
    burnt on this failed attempt -- a second, valid response against the
    same challenge id must also be rejected, not silently accepted."""
    make_oauth_token(alice)
    challenge_id, options = service.begin_recover(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_recover(alice, challenge_id, authenticator.register(options, uv=False))
    assert Passkey.objects.count() == 0
    assert Token.objects.filter(user=alice).exists()
    assert AccessToken.objects.filter(user=alice).exists()
    assert len(mail.outbox) == 0
    with pytest.raises(service.RegistrationFailed):
        service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert Passkey.objects.count() == 0
    assert len(mail.outbox) == 0


def test_finish_recover_rejects_wrong_user_and_burns_challenge(alice, bob, authenticator):
    """A recovery challenge issued to alice can't be finished as bob, and
    the attempt still burns the challenge (it's gone either way once
    consumed, successfully or not)."""
    make_oauth_token(alice)
    challenge_id, options = service.begin_recover(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_recover(bob, challenge_id, authenticator.register(options))
    assert Passkey.objects.count() == 0
    assert Token.objects.filter(user=alice).exists()
    assert len(mail.outbox) == 0
    with pytest.raises(service.RegistrationFailed):
        service.finish_recover(alice, challenge_id, SoftAuthenticator().register(options))


def test_finish_recover_rejects_credential_already_registered_to_another_user(alice, bob, authenticator):
    """The same physical authenticator can't be used to recover alice's
    account when its credential is already bob's -- the unique constraint
    on credential_id must surface as RegistrationFailed, from transaction
    B, never retried (it isn't an OperationalError), and must not touch
    mail. Transaction A has already committed by the time B fails this
    way, so alice's own tokens are revoked regardless -- the intended,
    fail-safe split outcome finish_recover's docstring describes, not a
    bug: she is signed out of every API client and can simply retry."""
    add_passkey(bob, authenticator)  # sends bob his own passkey-added email
    outbox_before = len(mail.outbox)
    make_oauth_token(alice)
    challenge_id, options = service.begin_recover(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert Passkey.objects.filter(user=alice).count() == 0
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert len(mail.outbox) == outbox_before


def test_finish_recover_rejects_reused_challenge(alice, authenticator):
    challenge_id, options = service.begin_recover(alice)
    service.finish_recover(alice, challenge_id, authenticator.register(options))
    with pytest.raises(service.RegistrationFailed):
        service.finish_recover(alice, challenge_id, SoftAuthenticator().register(options))
    assert Passkey.objects.count() == 1
    assert len(mail.outbox) == 1


def test_finish_recover_works_for_passkey_only_user(alice, authenticator):
    alice.set_unusable_password()
    alice.save(update_fields=['password'])
    make_oauth_token(alice)
    challenge_id, options = service.begin_recover(alice)
    passkey = service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert passkey.user == alice
    assert not AccessToken.objects.filter(user=alice).exists()
    assert len(mail.outbox) == 1


def test_finish_recover_signs_out_existing_sessions_for_passkey_only_user(alice, authenticator):
    """delete_user_sessions signs a passkey-only user's existing browser
    session out exactly the same way it does for anyone else -- a
    regression check that recovery still covers this user shape (it used
    to also rotate an unusable-password hash for this case specifically;
    that's gone now that the session scan covers every user)."""
    alice.set_unusable_password()
    alice.save(update_fields=['password'])
    old_client = Client()
    old_client.force_login(alice)
    assert old_client.get('/user_data/').status_code == 200

    challenge_id, options = service.begin_recover(alice)
    passkey = service.finish_recover(alice, challenge_id, authenticator.register(options))

    resp = old_client.get('/user_data/')
    assert resp.status_code == 302
    assert resp['Location'].startswith('/login/')

    new_client = Client()
    new_client.force_login(passkey.user)
    assert new_client.get('/user_data/').status_code == 200


def test_finish_recover_signs_out_existing_sessions_for_password_user(alice, authenticator):
    """A password user's session does not carry a stale auth hash the way
    revoke_all_tokens or a passkey-only user's hash rotation would catch --
    recovery deliberately leaves their password untouched -- so
    delete_user_sessions is what has to sign this browser out instead."""
    old_client = Client()
    old_client.force_login(alice)
    assert old_client.get('/user_data/').status_code == 200

    challenge_id, options = service.begin_recover(alice)
    service.finish_recover(alice, challenge_id, authenticator.register(options))

    resp = old_client.get('/user_data/')
    assert resp.status_code == 302
    assert resp['Location'].startswith('/login/')
    # the password itself is untouched -- only the session row was deleted
    assert alice.check_password('alicepass123')


def test_finish_recover_keep_session_key_preserves_that_session(alice, authenticator):
    """The recovering browser's own session, when it's already logged in
    as the account being recovered, must survive if the caller says so --
    every other session for the same user still goes."""
    kept_client = Client()
    kept_client.force_login(alice)
    keep_key = kept_client.session.session_key
    other_client = Client()
    other_client.force_login(alice)
    assert kept_client.get('/user_data/').status_code == 200
    assert other_client.get('/user_data/').status_code == 200

    challenge_id, options = service.begin_recover(alice)
    service.finish_recover(alice, challenge_id, authenticator.register(options),
                           keep_session_key=keep_key)

    assert kept_client.get('/user_data/').status_code == 200
    other_resp = other_client.get('/user_data/')
    assert other_resp.status_code == 302
    assert other_resp['Location'].startswith('/login/')


def test_finish_recover_never_stores_a_passkey_when_transaction_a_fails(alice, authenticator,
                                                                        monkeypatch):
    """Transaction A (revoke_all_tokens) runs, and must fully fail, before
    transaction B ever starts: a non-retryable error there must propagate
    immediately, leaving no passkey stored, the account's tokens
    untouched (this fake never actually deletes anything), and no
    passkey-added email for a ceremony B never got to."""
    make_oauth_token(alice)

    def _boom(_user):
        raise RuntimeError('boom')

    monkeypatch.setattr(service, 'revoke_all_tokens', _boom)
    challenge_id, options = service.begin_recover(alice)
    with pytest.raises(RuntimeError):
        service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert Passkey.objects.count() == 0
    assert Token.objects.filter(user=alice).exists()
    assert AccessToken.objects.filter(user=alice).exists()
    assert len(mail.outbox) == 0


def test_finish_recover_keeps_token_revocation_when_transaction_b_fails(alice, authenticator,
                                                                        monkeypatch):
    """A session-deletion failure aborts transaction B (no passkey stored,
    no email), but transaction A has already committed by then -- so,
    unlike a failure inside A, alice's tokens stay revoked. This is the
    intended, fail-safe split outcome finish_recover's docstring
    describes: she is signed out of every API client already and can
    simply retry the passkey ceremony."""
    make_oauth_token(alice)

    def _boom(_user, keep_session_key=None):
        raise RuntimeError('boom')

    monkeypatch.setattr(service, 'delete_user_sessions', _boom)
    challenge_id, options = service.begin_recover(alice)
    with pytest.raises(RuntimeError):
        service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert Passkey.objects.count() == 0
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert len(mail.outbox) == 0


def test_finish_recover_sweeps_tokens_minted_during_the_transaction(alice, authenticator, monkeypatch):
    """A session or request live throughout transaction A can still mint a
    brand-new Grant/AccessToken/RefreshToken at any point during it --
    after the Grant delete, the refresh delete, the access delete, even
    before any of them run -- because DOT validates both a Grant and a
    refresh token with a plain, unlocked SELECT. That mint survives A's
    commit since it never conflicted with anything A deleted.
    finish_recover has to sweep again after commit to actually close
    this, not just narrow it -- so this also pins the sweep's *position*:
    recording the atomic-block nesting depth on each call catches a
    regression where the second call moves back inside a transaction
    (which would still pass every other assertion here, since a revoke
    from inside an about-to-commit transaction also happens to delete
    rows that were only ever created within that same transaction in this
    particular test)."""
    real_revoke = service.revoke_all_tokens
    calls = []
    depths = []

    def _revoke_then_mint(user):
        calls.append(user)
        # pytest-django wraps the whole test in its own atomic block(s), so
        # 0 is never the baseline -- what matters is that the second call
        # is shallower than the first, i.e. it runs after transaction A's
        # own `with transaction.atomic():` (opened by _run_with_retry) has
        # exited. revoke_all_tokens is only ever called from A and from
        # the post-commit sweep -- transaction B never calls it at all.
        depths.append(len(connection.atomic_blocks))
        real_revoke(user)
        if len(calls) == 1:
            # Stand in for the concurrent mint: whenever A's own revoke
            # actually runs, a fresh set of credentials appears for this
            # user, as if a racing request just finished.
            access = make_oauth_token(user)
            RefreshToken.objects.create(user=user, application=access.application,
                                        token='concurrent-r', access_token=access)
            Grant.objects.create(user=user, application=access.application,
                                 code='concurrent-c',
                                 expires=timezone.now() + timedelta(minutes=5),
                                 redirect_uri='https://app.example/cb',
                                 scope='etipitaka:read')

    monkeypatch.setattr(service, 'revoke_all_tokens', _revoke_then_mint)
    challenge_id, options = service.begin_recover(alice)
    passkey = service.finish_recover(alice, challenge_id, authenticator.register(options))

    assert passkey.user == alice
    assert len(calls) == 2  # transaction A's own call, then the post-commit sweep
    assert depths[1] < depths[0]  # the sweep runs strictly outside transaction A
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert not RefreshToken.objects.filter(user=alice).exists()
    assert not Grant.objects.filter(user=alice).exists()


def test_finish_recover_logs_when_post_commit_sweep_fails(alice, authenticator, monkeypatch, caplog):
    """The post-commit sweep is best-effort, like the email: recovery has
    already committed by the time it runs, so a failure there must not
    come back as an exception the caller has to treat as a failed
    recovery -- the passkey is real and already stored."""
    real_revoke = service.revoke_all_tokens
    calls = []

    def _revoke_once_then_fail(user):
        calls.append(user)
        if len(calls) == 1:
            real_revoke(user)
        else:
            raise RuntimeError('sweep boom')

    monkeypatch.setattr(service, 'revoke_all_tokens', _revoke_once_then_fail)
    challenge_id, options = service.begin_recover(alice)
    passkey = service.finish_recover(alice, challenge_id, authenticator.register(options))

    assert passkey.user == alice
    assert Passkey.objects.filter(pk=passkey.pk).exists()
    assert any(record.name == 'user_data.passkey_service' and record.levelname == 'ERROR'
              for record in caplog.records)


# --- recovery splits into two separate, lock-ordered transactions ----------

@pytest.mark.django_db(transaction=True)
def test_finish_recover_runs_revoke_and_store_in_separate_transactions(alice, authenticator,
                                                                        monkeypatch):
    """Transaction A (revoke_all_tokens) and transaction B (_store_passkey,
    then delete_user_sessions) must be genuinely separate top-level
    Postgres transactions -- the whole point of the split (see
    finish_recover's docstring) is that neither one ever holds a
    token-table lock and the user-row lock at the same time.
    connection.atomic_blocks[0] is the currently open outermost Atomic
    instance for this connection (or the list is empty when nothing is
    open); recording *the object itself* (not just its id()) at each call
    site, in a list this test keeps a live reference to throughout, is
    enough to tell whether two calls shared one top-level transaction,
    ran in two separate ones, or ran with no transaction open at all --
    true of the post-commit sweep, which runs after both A and B have
    already committed. Comparing id() instead would be unsound: A's own
    Atomic instance is garbage-collected the moment A's `with` block
    exits, and CPython can and does immediately reuse that exact address
    for B's -- which is exactly what a first version of this test found,
    the two id()s equal despite genuinely separate transactions. Keeping
    the objects alive in `txn_blocks` for the rest of the test and
    comparing with `is`/`is not` sidesteps that entirely. A second,
    independent check on the query log proves the stronger property the
    split exists for: no Grant/RefreshToken/AccessToken/IDToken SQL runs
    while B is open."""
    real_revoke = service.revoke_all_tokens
    real_store = service._store_passkey
    real_delete_sessions = service.delete_user_sessions
    token_tables = [Grant._meta.db_table, RefreshToken._meta.db_table,
                    AccessToken._meta.db_table, IDToken._meta.db_table]
    txn_blocks = {}
    b_bounds = {}

    def _current_block():
        return connection.atomic_blocks[0] if connection.atomic_blocks else None

    def _revoke(user):
        txn_blocks.setdefault('revoke', []).append(_current_block())
        return real_revoke(user)

    def _store(*args, **kwargs):
        txn_blocks.setdefault('store', []).append(_current_block())
        b_bounds['start'] = len(ctx.captured_queries)
        return real_store(*args, **kwargs)

    def _delete_sessions(*args, **kwargs):
        txn_blocks.setdefault('delete_sessions', []).append(_current_block())
        result = real_delete_sessions(*args, **kwargs)
        b_bounds['end'] = len(ctx.captured_queries)
        return result

    monkeypatch.setattr(service, 'revoke_all_tokens', _revoke)
    monkeypatch.setattr(service, '_store_passkey', _store)
    monkeypatch.setattr(service, 'delete_user_sessions', _delete_sessions)

    challenge_id, options = service.begin_recover(alice)
    with CaptureQueriesContext(connection) as ctx:
        service.finish_recover(alice, challenge_id, authenticator.register(options))

    # A's own call and B's calls never share a top-level transaction; B's
    # two calls (_store_passkey, delete_user_sessions) share the same one.
    assert txn_blocks['revoke'][0] is not None
    assert txn_blocks['store'][0] is not None
    assert txn_blocks['revoke'][0] is not txn_blocks['store'][0]
    assert txn_blocks['store'][0] is txn_blocks['delete_sessions'][0]
    # The post-commit sweep (revoke_all_tokens's second call) runs with no
    # atomic block open at all -- strictly outside both A and B.
    assert txn_blocks['revoke'][1] is None

    b_queries = ctx.captured_queries[b_bounds['start']:b_bounds['end']]
    assert b_queries  # the window is real, not an empty slice
    assert not any(table in q['sql'] for q in b_queries for table in token_tables)


# --- recovery retries on deadlock --------------------------------------------
# A concurrent OAuth refresh-token rotation can lock RefreshToken and then
# AccessToken rows before its commit needs the user row's key-share lock
# (see finish_recover's docstring for the full cycle this used to allow).
# Splitting recovery into transaction A (revoke_all_tokens, never touches
# the user row) and transaction B (_store_passkey then delete_user_sessions,
# never touches a token-table row) removes that cycle outright. Both
# transactions still carry the same retry backstop for whatever contention
# the split does not itself rule out -- exercised here by monkeypatching
# the one call each transaction makes to raise the same shape of error a
# real driver would, rather than provoking a real deadlock between threads.

def _raise_deadlock():
    cause = psycopg.errors.DeadlockDetected('deadlock detected')
    raise OperationalError('deadlock detected') from cause


def test_finish_recover_retries_once_in_a_on_deadlock_then_succeeds(alice, authenticator,
                                                                     monkeypatch):
    make_oauth_token(alice)
    real_revoke = service.revoke_all_tokens
    calls = {'n': 0}

    def _flaky_revoke(user):
        calls['n'] += 1
        if calls['n'] == 1:
            _raise_deadlock()
        return real_revoke(user)

    monkeypatch.setattr(service, 'revoke_all_tokens', _flaky_revoke)
    monkeypatch.setattr(service.time, 'sleep', lambda *_a, **_kw: None)

    challenge_id, options = service.begin_recover(alice)
    passkey = service.finish_recover(alice, challenge_id, authenticator.register(options))

    assert passkey.user == alice
    assert Passkey.objects.filter(user=alice).count() == 1  # B only ever ran once
    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert len(mail.outbox) == 1


def test_finish_recover_gives_up_after_max_deadlock_retries_in_a(alice, authenticator, monkeypatch):
    calls = {'n': 0}

    def _always_deadlocks(_user):
        calls['n'] += 1
        _raise_deadlock()

    monkeypatch.setattr(service, 'revoke_all_tokens', _always_deadlocks)
    monkeypatch.setattr(service.time, 'sleep', lambda *_a, **_kw: None)

    challenge_id, options = service.begin_recover(alice)
    with pytest.raises(OperationalError):
        service.finish_recover(alice, challenge_id, authenticator.register(options))

    assert calls['n'] == service._MAX_RECOVERY_ATTEMPTS
    assert not Passkey.objects.filter(user=alice).exists()  # B never even started
    assert len(mail.outbox) == 0


def test_finish_recover_does_not_retry_a_non_deadlock_operational_error_in_a(alice, authenticator,
                                                                             monkeypatch):
    calls = {'n': 0}

    def _unrelated_operational_error(_user):
        calls['n'] += 1
        raise OperationalError('server closed the connection unexpectedly')

    monkeypatch.setattr(service, 'revoke_all_tokens', _unrelated_operational_error)
    monkeypatch.setattr(service.time, 'sleep', lambda *_a, **_kw: None)

    challenge_id, options = service.begin_recover(alice)
    with pytest.raises(OperationalError):
        service.finish_recover(alice, challenge_id, authenticator.register(options))

    assert calls['n'] == 1  # no retry: this is not a deadlock or serialization failure
    assert not Passkey.objects.filter(user=alice).exists()
    assert len(mail.outbox) == 0


def test_finish_recover_retries_once_in_b_on_deadlock_then_succeeds(alice, authenticator,
                                                                     monkeypatch):
    """The same backstop applies to transaction B independently of A: a
    failed B attempt rolls its own passkey insert back together with the
    rest of B (delete_user_sessions never having run yet), so the retry
    starts clean and stores exactly one passkey, never two."""
    real_delete_sessions = service.delete_user_sessions
    calls = {'n': 0}

    def _flaky_delete_sessions(user, keep_session_key=None):
        calls['n'] += 1
        if calls['n'] == 1:
            _raise_deadlock()
        return real_delete_sessions(user, keep_session_key=keep_session_key)

    monkeypatch.setattr(service, 'delete_user_sessions', _flaky_delete_sessions)
    monkeypatch.setattr(service.time, 'sleep', lambda *_a, **_kw: None)

    challenge_id, options = service.begin_recover(alice)
    passkey = service.finish_recover(alice, challenge_id, authenticator.register(options))

    assert passkey.user == alice
    assert Passkey.objects.filter(user=alice).count() == 1  # the failed B attempt rolled back
    assert len(mail.outbox) == 1


def test_finish_recover_gives_up_after_max_deadlock_retries_in_b(alice, authenticator, monkeypatch):
    calls = {'n': 0}

    def _always_deadlocks(_user, keep_session_key=None):
        calls['n'] += 1
        _raise_deadlock()

    monkeypatch.setattr(service, 'delete_user_sessions', _always_deadlocks)
    monkeypatch.setattr(service.time, 'sleep', lambda *_a, **_kw: None)

    challenge_id, options = service.begin_recover(alice)
    with pytest.raises(OperationalError):
        service.finish_recover(alice, challenge_id, authenticator.register(options))

    assert calls['n'] == service._MAX_RECOVERY_ATTEMPTS
    assert not Passkey.objects.filter(user=alice).exists()  # every attempt's insert rolled back
    assert len(mail.outbox) == 0


def test_finish_recover_checks_session_engine_before_consuming_challenge(alice, authenticator,
                                                                          settings):
    """A misconfigured SESSION_ENGINE must be caught before the one-time
    recovery challenge is burnt -- delete_user_sessions would fail deep
    inside the atomic block anyway, but only after the challenge that
    can't be replayed is already gone."""
    challenge_id, options = service.begin_recover(alice)
    settings.SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
    with pytest.raises(ImproperlyConfigured):
        service.finish_recover(alice, challenge_id, authenticator.register(options))
    assert WebAuthnChallenge.objects.filter(pk=challenge_id).exists()


def test_begin_recover_checks_session_engine(alice, settings):
    settings.SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
    with pytest.raises(ImproperlyConfigured):
        service.begin_recover(alice)
