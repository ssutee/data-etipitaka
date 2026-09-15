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


@pytest.mark.parametrize('credential', [None, 'x', [], {}])
def test_finish_register_rejects_malformed_credential(alice, credential):
    challenge_id, _options = service.begin_register(alice)
    with pytest.raises(service.RegistrationFailed):
        service.finish_register(alice, challenge_id, credential)


def test_android_origin_accepted_when_configured(alice, authenticator, settings):
    fingerprint = ':'.join(['01'] * 32)
    settings.PASSKEY_ANDROID_CERT_SHA256 = [fingerprint]
    assert _register(alice, authenticator, origin=android_origin(fingerprint)).pk
