import secrets

import cbor2
import pytest
from django.core import mail

from user_data import passkey_service as service
from user_data.models import Passkey, PasskeyUserHandle, WebAuthnChallenge
from user_data.passkey_config import android_origin

from .soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.django_db

APPLE_AAGUID = bytes.fromhex('fbfc3007154e4ecc8c0b6e020557d7bd')


def _register(user, authenticator, name=None, **tamper):
    challenge_id, options = service.begin_register(user)
    return service.finish_register(user, challenge_id,
                                   authenticator.register(options, **tamper), name=name)


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


# --- malformed / hostile WebAuthn responses ---------------------------------
# py_webauthn 3.0.0 parses attacker-controlled CBOR without fully guarding
# against structurally-invalid input; these crash with raw TypeError/KeyError/
# IndexError/ValueError instead of its own WebAuthnException subclasses.

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


def test_finish_register_rejects_packed_attestation_with_junk_x5c(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    att_stmt = {'alg': -7, 'sig': secrets.token_bytes(64), 'x5c': [secrets.token_bytes(50)]}
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id,
                                authenticator.register(options, fmt='packed', att_stmt=att_stmt))
    assert not Passkey.objects.exists()


def test_finish_register_rejects_tpm_attestation_with_junk_fields(alice, authenticator):
    challenge_id, options = service.begin_register(alice)
    att_stmt = {'ver': '2.0', 'alg': -7, 'x5c': [secrets.token_bytes(50)],
                'sig': secrets.token_bytes(64), 'certInfo': secrets.token_bytes(50),
                'pubArea': secrets.token_bytes(50)}
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id,
                                authenticator.register(options, fmt='tpm', att_stmt=att_stmt))
    assert not Passkey.objects.exists()


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

def test_finish_register_keeps_passkey_when_email_fails(alice, authenticator, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError('smtp is down')
    monkeypatch.setattr(service, 'send_mail', _boom)
    passkey = _register(alice, authenticator)
    assert Passkey.objects.filter(pk=passkey.pk).exists()


# --- clean_name hardening ----------------------------------------------------

@pytest.mark.parametrize('raw,expected', [
    ('Ali\x00ce', 'Alice'),           # NUL (Cc)
    ('Ali\ud800ce', 'Alice'),         # lone surrogate (Cs)
    ('Ali‮ce', 'Alice'),         # RTL override (Cf)
    ('Ali‍ce', 'Ali‍ce'),   # ZWJ (Cf) is explicitly kept
], ids=['nul', 'lone-surrogate', 'bidi-override', 'zwj-kept'])
def test_clean_name_strips_disallowed_categories(raw, expected):
    assert service.clean_name(raw) == expected


def test_clean_name_strips_newline_injection():
    cleaned = service.clean_name('My phone\nX-Injected: header')
    assert '\n' not in cleaned
    assert '\r' not in cleaned


def test_clean_name_truncates_then_strips_trailing_space_at_cut():
    assert service.clean_name('a' * 99 + ' b') == 'a' * 99


def test_clean_name_collapses_internal_whitespace():
    assert service.clean_name('  My   phone  ') == 'My phone'


def test_clean_name_whitespace_only_returns_empty():
    assert service.clean_name('   ') == ''


@pytest.mark.parametrize('value', [123, {'a': 1}, ['x']])
def test_clean_name_non_string_returns_empty(value):
    assert service.clean_name(value) == ''
