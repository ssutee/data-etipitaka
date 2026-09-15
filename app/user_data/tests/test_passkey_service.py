import json
import secrets

import cbor2
import pytest
from django.contrib.auth.models import User
from django.core import mail

from user_data import passkey_service as service
from user_data.models import Passkey, PasskeyUserHandle, WebAuthnChallenge
from user_data.passkey_config import android_origin

from .conftest import add_passkey, login_assertion
from .soft_authenticator import SoftAuthenticator, b64url

pytestmark = pytest.mark.django_db

APPLE_AAGUID = bytes.fromhex('fbfc3007154e4ecc8c0b6e020557d7bd')

# Unicode characters referenced by name below, built with chr() rather than
# embedded literally so the source file stays plain ASCII.
ZWJ = chr(0x200D)          # zero-width joiner
RTL_OVERRIDE = chr(0x202E)  # right-to-left override
ZWSP = chr(0x200B)          # zero-width space


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


def test_step_up_with_own_passkey(alice, authenticator):
    add_passkey(alice, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    service.verify_step_up(alice, assertion={'challenge_id': challenge_id,
                                             'credential': credential})


def test_step_up_rejects_other_users_passkey(alice, bob, authenticator):
    add_passkey(bob, authenticator)
    challenge_id, credential = login_assertion(authenticator)
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, assertion={'challenge_id': challenge_id,
                                                 'credential': credential})


@pytest.mark.parametrize('assertion', [None, 'x', {}, {'challenge_id': 'nope', 'credential': {}}])
def test_step_up_rejects_missing_or_bad_assertion(alice, assertion):
    with pytest.raises(service.StepUpFailed):
        service.verify_step_up(alice, assertion=assertion)
