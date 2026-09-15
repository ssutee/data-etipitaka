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

from django.conf import settings
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.template.loader import render_to_string
from django.utils.translation import gettext as _
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
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


class PasskeyError(Exception):
    """Base class for failures the views turn into 4xx responses."""


class RegistrationFailed(PasskeyError):
    """The challenge or the registration response did not verify."""


def clean_name(name):
    return name.strip()[:100] if isinstance(name, str) else ''


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
        return verify_registration_response(
            credential=credential, expected_challenge=challenge,
            expected_rp_id=config.rp_id(), expected_origin=config.expected_origins(),
            require_user_verification=True)
    except WebAuthnException as exc:
        log.info('passkey registration rejected: %s', type(exc).__name__)
        raise RegistrationFailed() from exc


def _store_passkey(user, verified, credential, name):
    aaguid = str(verified.aaguid)
    transports = [t for t in (credential.get('response') or {}).get('transports') or []
                  if isinstance(t, str) and t in _TRANSPORTS]
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
    send_mail(_('A passkey was added to your E-Tipitaka account'), body,
              settings.DEFAULT_FROM_EMAIL, [user.email])


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
