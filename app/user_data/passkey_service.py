"""Passkey ceremonies: registration, login, step-up, signup and recovery.

Plain functions over users and WebAuthn JSON dicts -- never a request -- so
the views stay thin and every rule is testable without HTTP. py_webauthn
performs the cryptographic checks (signature, RP ID hash, origin, UV flag,
sign counter); this module owns challenges, account rules and persistence.
See docs/superpowers/specs/2026-09-14-passkey-login-design.md.
"""
import json
import logging
import secrets
import unicodedata

from django.conf import settings
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.template.loader import render_to_string
from django.utils.translation import gettext as _
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import (base64url_to_bytes, bytes_to_base64url,
                              decode_credential_public_key,
                              decoded_public_key_to_cryptography)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (AttestationConveyancePreference,
                                      AuthenticatorSelectionCriteria,
                                      AuthenticatorTransport,
                                      PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement,
                                      UserVerificationRequirement)

from . import passkey_challenges as challenges
from . import passkey_config as config
from .models import Passkey, PasskeyUserHandle, WebAuthnChallenge

log = logging.getLogger(__name__)

# Display names of common passkey providers, keyed by AAGUID
# (github.com/passkeydeveloper/passkey-authenticator-aaguids).
AAGUID_NAMES = {
    'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'Apple Passwords',
    'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (Managed)',
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
    '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
    '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
    'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
    'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
}
_TRANSPORTS = {t.value for t in AuthenticatorTransport}
# Unicode general categories stripped from passkey names: control (Cc),
# format (Cf, except the ZWJ used in emoji sequences), surrogate (Cs),
# private-use (Co), unassigned (Cn), and the line/paragraph separators.
_NAME_STRIP_CATEGORIES = {'Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp'}
_NAME_KEEP_CHAR = '‍'  # zero-width joiner
_MAX_CREDENTIAL_ID_LENGTH = 1023


class PasskeyError(Exception):
    """Base class for failures the views turn into 4xx responses."""


class RegistrationFailed(PasskeyError):
    """The challenge or the registration response did not verify."""


def clean_name(name):
    """Sanitize a user-supplied passkey name; '' means "use the default".

    Strips characters that could inject headers/newlines into the
    added-passkey email or spoof the reader with bidi overrides, collapses
    whitespace, then truncates -- in that order, so a truncation cut never
    leaves trailing whitespace.
    """
    if not isinstance(name, str):
        return ''
    filtered = ''.join(ch for ch in name if ch == _NAME_KEEP_CHAR
                       or unicodedata.category(ch) not in _NAME_STRIP_CATEGORIES)
    return ' '.join(filtered.split())[:100].strip()


def _options_json(options):
    return json.loads(options_to_json(options))


def _consume(challenge_id, purpose, user, error):
    try:
        return challenges.consume(challenge_id, purpose, user=user)
    except challenges.ChallengeError as exc:
        raise error() from exc


def _handle_for(user):
    row, _created = PasskeyUserHandle.objects.get_or_create(
        user=user, defaults={'handle': secrets.token_bytes(32)})
    return bytes(row.handle)


def _descriptors(user):
    return [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(p.credential_id),
            transports=[AuthenticatorTransport(t) for t in p.transports if t in _TRANSPORTS])
        for p in user.passkeys.order_by('pk')
    ]


def _registration_options(challenge, username, handle, exclude):
    return _options_json(generate_registration_options(
        rp_id=config.rp_id(), rp_name=settings.PASSKEY_RP_NAME,
        user_name=username, user_id=handle, user_display_name=username,
        challenge=challenge, timeout=settings.PASSKEY_CHALLENGE_TTL * 1000,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=exclude))


def _verify_registration(challenge, credential):
    if not isinstance(credential, dict):
        raise RegistrationFailed()
    try:
        # py_webauthn parses attacker-controlled CBOR (the COSE public key,
        # the attestation statement) without fully guarding against
        # structurally-invalid input, so a crafted response can raise a raw
        # TypeError/KeyError/IndexError/ValueError (binascii.Error included)
        # instead of one of its own WebAuthnException subclasses.
        verified = verify_registration_response(
            credential=credential, expected_challenge=challenge,
            expected_rp_id=config.rp_id(), expected_origin=config.expected_origins(),
            require_user_verification=True)
        # A key can pass verification (e.g. fmt "none" never inspects it)
        # yet still not be a usable point/modulus -- decode it for real now
        # so junk never gets stored only to break the first login attempt.
        decoded_public_key_to_cryptography(
            decode_credential_public_key(verified.credential_public_key))
    except (WebAuthnException, ValueError, KeyError, TypeError, IndexError) as exc:
        log.info('passkey registration rejected: %s', type(exc).__name__)
        raise RegistrationFailed() from exc
    if len(verified.credential_id) > _MAX_CREDENTIAL_ID_LENGTH:
        raise RegistrationFailed()
    return verified


def _store_passkey(user, verified, credential, name):
    aaguid = str(verified.aaguid)
    raw_transports = (credential.get('response') or {}).get('transports')
    transports = ([t for t in raw_transports if isinstance(t, str) and t in _TRANSPORTS]
                  if isinstance(raw_transports, list) else [])
    try:
        with transaction.atomic():
            return Passkey.objects.create(
                user=user, credential_id=bytes_to_base64url(verified.credential_id),
                public_key=verified.credential_public_key,
                sign_count=verified.sign_count, transports=transports, aaguid=aaguid,
                backed_up=verified.credential_backed_up,
                name=clean_name(name) or AAGUID_NAMES.get(aaguid, 'Passkey'))
    except IntegrityError as exc:  # credential already registered to some account
        raise RegistrationFailed() from exc


def _send_passkey_added_email(user, passkey):
    if not user.email:
        return
    body = render_to_string('email/passkey_added.txt', {
        'username': user.username, 'passkey_name': passkey.name,
        'security_url': config.web_origin() + '/account/security/',
        'reset_url': config.web_origin() + '/password_reset/'})
    try:
        send_mail(_('A passkey was added to your E-Tipitaka account'), body,
                  settings.DEFAULT_FROM_EMAIL, [user.email])
    except Exception:  # a mail outage must not look like a failed registration
        log.exception('failed to send passkey-added email to user %s', user.pk)


def _begin_registration(user, purpose):
    row = challenges.create(purpose, user=user)
    return row.id, _registration_options(row.challenge, user.username,
                                         _handle_for(user), _descriptors(user))


def _finish_registration(user, purpose, challenge_id, credential, name):
    row = _consume(challenge_id, purpose, user, RegistrationFailed)
    verified = _verify_registration(row.challenge, credential)
    return _store_passkey(user, verified, credential, name)


def begin_register(user):
    """Options for adding a passkey to a signed-in account (after step-up)."""
    return _begin_registration(user, WebAuthnChallenge.REGISTER)


def finish_register(user, challenge_id, credential, name=None):
    passkey = _finish_registration(user, WebAuthnChallenge.REGISTER,
                                   challenge_id, credential, name)
    _send_passkey_added_email(user, passkey)
    return passkey
