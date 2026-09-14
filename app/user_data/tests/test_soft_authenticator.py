import pytest
from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers.exceptions import InvalidAuthenticationResponse

from .soft_authenticator import SoftAuthenticator, b64url

CHALLENGE = b'c' * 32
RP = 'data.etipitaka.com'
ORIGIN = 'https://data.etipitaka.com'
REG_OPTIONS = {'rp': {'id': RP, 'name': 'E-Tipitaka'},
               'user': {'id': b64url(b'h' * 32), 'name': 'alice', 'displayName': 'alice'},
               'challenge': b64url(CHALLENGE)}
AUTH_OPTIONS = {'rpId': RP, 'challenge': b64url(CHALLENGE)}


def _register(authenticator):
    return verify_registration_response(
        credential=authenticator.register(REG_OPTIONS), expected_challenge=CHALLENGE,
        expected_rp_id=RP, expected_origin=ORIGIN, require_user_verification=True)


def _authenticate(authenticator, verified, **tamper):
    return verify_authentication_response(
        credential=authenticator.assert_(AUTH_OPTIONS, **tamper),
        expected_challenge=CHALLENGE, expected_rp_id=RP, expected_origin=ORIGIN,
        credential_public_key=verified.credential_public_key,
        credential_current_sign_count=0, require_user_verification=True)


def test_registration_verifies():
    authenticator = SoftAuthenticator()
    verified = _register(authenticator)
    assert verified.user_verified is True
    assert verified.credential_backed_up is True
    assert authenticator.user_handle == b'h' * 32


def test_assertion_verifies_and_counts():
    authenticator = SoftAuthenticator()
    verified = _register(authenticator)
    assert _authenticate(authenticator, verified).new_sign_count == 1


def test_corrupt_signature_is_rejected():
    authenticator = SoftAuthenticator()
    verified = _register(authenticator)
    with pytest.raises(InvalidAuthenticationResponse):
        _authenticate(authenticator, verified, corrupt_signature=True)
