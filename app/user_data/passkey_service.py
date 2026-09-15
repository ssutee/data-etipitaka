"""Passkey ceremonies: registration, login, step-up, signup and recovery.

Plain functions over users and WebAuthn JSON dicts -- never a request -- so
the views stay thin and every rule is testable without HTTP. py_webauthn
performs the cryptographic checks (signature, RP ID hash, origin, UV flag,
sign counter); this module owns challenges, account rules and persistence.
See docs/superpowers/specs/2026-09-14-passkey-login-design.md.
"""
import hmac
import json
import logging
import secrets
import unicodedata

from django.conf import settings
from django.contrib.auth.models import update_last_login
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.translation import gettext as _
from webauthn import (generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers import (base64url_to_bytes, bytes_to_base64url,
                              decode_credential_public_key,
                              decoded_public_key_to_cryptography,
                              encode_cbor, parse_authentication_credential_json,
                              parse_cbor)
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
_NAME_KEEP_CHAR = chr(0x200D)  # zero-width joiner, kept in passkey names for emoji sequences
_MAX_CREDENTIAL_ID_LENGTH = 1023


class PasskeyError(Exception):
    """Base class for failures the views turn into 4xx responses."""


class RegistrationFailed(PasskeyError):
    """The challenge or the registration response did not verify."""


class InvalidCredentials(PasskeyError):
    """The challenge or the assertion did not verify (deliberately generic)."""


class InactiveUser(PasskeyError):
    """The assertion verified but the account's email is not verified yet."""


class StepUpFailed(PasskeyError):
    """Neither a password nor a passkey assertion proved the account holder."""


def clean_name(name):
    """Sanitize a user-supplied passkey name; '' means "use the default".

    Order matters: collapse whitespace FIRST (so a control character used as
    a word separator, e.g. a tab or newline, still leaves a single space
    behind rather than merging the words either side of it), THEN strip
    characters that could inject headers/newlines into the added-passkey
    email or spoof the reader with bidi overrides, THEN collapse again
    (filtering can turn two spaces that used to flank a now-deleted
    character into an adjacent pair), then truncate and strip so a
    truncation cut never leaves trailing whitespace. A name left with no
    visible character (e.g. only zero-width joiners) is treated as empty.
    """
    if not isinstance(name, str):
        return ''
    collapsed = ' '.join(name.split())
    filtered = ''.join(ch for ch in collapsed if ch == _NAME_KEEP_CHAR
                       or unicodedata.category(ch) not in _NAME_STRIP_CATEGORIES)
    cleaned = ' '.join(filtered.split())[:100].strip()
    if not cleaned.replace(_NAME_KEEP_CHAR, '').strip():
        return ''
    return cleaned


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


def _neutralize_attestation(credential):
    """Discard the attestation statement before verification.

    We request attestation "none" and never trust whatever an authenticator
    actually sends, so there is no reason for py_webauthn's packed/tpm/
    android-key/apple/android-safetynet/fido-u2f parsers to ever run on
    attacker-controlled attStmt bytes -- e.g. a crafted android-safetynet
    response raises a raw AttributeError deep inside py_webauthn instead of
    one of its own exception types. Keep only authData: RP ID hash, the UV
    flag, and the credential id/public key are all read from it, and none
    of that requires an attestation statement at all.

    parse_cbor/encode_cbor (rather than calling cbor2 directly) wrap every
    decode failure in WebAuthnException's own InvalidCBORData, and
    parse_cbor rejects duplicate map keys.
    """
    attestation_object = parse_cbor(base64url_to_bytes(credential['response']['attestationObject']))
    auth_data = attestation_object['authData']
    if not isinstance(auth_data, bytes):
        raise TypeError('authData was not bytes')
    neutral = encode_cbor({'fmt': 'none', 'attStmt': {}, 'authData': auth_data})
    credential = dict(credential)
    credential['response'] = dict(credential['response'])
    credential['response']['attestationObject'] = bytes_to_base64url(neutral)
    return credential


def _verify_registration(challenge, credential):
    # Read config before touching the (possibly hostile) credential at all:
    # a malformed setting -- e.g. PASSKEY_ANDROID_CERT_SHA256 -- must raise
    # loudly for every request, not get funnelled into a generic
    # RegistrationFailed by the except clause below.
    rp_id = config.rp_id()
    expected_origin = config.expected_origins()
    if not isinstance(credential, dict):
        raise RegistrationFailed()
    try:
        credential = _neutralize_attestation(credential)
        # py_webauthn parses attacker-controlled CBOR (the COSE public key)
        # without fully guarding against structurally-invalid input, so a
        # crafted response can still raise a raw TypeError/KeyError/
        # IndexError/ValueError (binascii.Error included) or AttributeError
        # instead of one of its own WebAuthnException subclasses. A
        # malformed attestationObject fails parse_cbor above as a clean
        # InvalidCBORData (a WebAuthnException) instead.
        verified = verify_registration_response(
            credential=credential, expected_challenge=challenge,
            expected_rp_id=rp_id, expected_origin=expected_origin,
            require_user_verification=True)
        # A key can pass verification (fmt "none" never inspects it) yet
        # still not be a usable point/modulus -- decode it for real now so
        # junk never gets stored only to break the first login attempt.
        decoded_public_key_to_cryptography(
            decode_credential_public_key(verified.credential_public_key))
    except (WebAuthnException, ValueError, KeyError, TypeError, IndexError,
            AttributeError) as exc:
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


def begin_login():
    """Options for a username-less login: the authenticator picks the account."""
    row = challenges.create(WebAuthnChallenge.LOGIN)
    return row.id, _options_json(generate_authentication_options(
        rp_id=config.rp_id(), challenge=row.challenge,
        timeout=settings.PASSKEY_CHALLENGE_TTL * 1000,
        user_verification=UserVerificationRequirement.REQUIRED))


def _verify_assertion(challenge_id, credential):
    """Verify a login assertion and return its Passkey with usage recorded."""
    # Read config before consuming the challenge or touching the (possibly
    # hostile) credential at all: a malformed setting -- e.g.
    # PASSKEY_ANDROID_CERT_SHA256 -- must raise loudly for every login
    # attempt, not get funnelled into a generic InvalidCredentials by the
    # widened except clauses below. Same lesson as _verify_registration.
    rp_id = config.rp_id()
    expected_origin = config.expected_origins()
    row = _consume(challenge_id, WebAuthnChallenge.LOGIN, None, InvalidCredentials)
    if not isinstance(credential, dict):
        raise InvalidCredentials()
    try:
        # py_webauthn parses an attacker-controlled assertion without fully
        # guarding against structurally-invalid input -- e.g. a userHandle
        # that isn't valid base64url can still raise a raw
        # binascii.Error/ValueError here instead of one of py_webauthn's
        # own WebAuthnException subclasses.
        parsed = parse_authentication_credential_json(credential)
    except (WebAuthnException, ValueError, KeyError, TypeError, IndexError,
            AttributeError) as exc:
        raise InvalidCredentials() from exc
    passkey = None
    if parsed.raw_id:
        passkey = (Passkey.objects.select_related('user')
                   .filter(credential_id=bytes_to_base64url(parsed.raw_id)).first())
    if passkey is None:
        raise InvalidCredentials()
    handle = (PasskeyUserHandle.objects.filter(user_id=passkey.user_id)
              .values_list('handle', flat=True).first())
    claimed = parsed.response.user_handle
    if handle is None or claimed is None or not hmac.compare_digest(bytes(handle), claimed):
        raise InvalidCredentials()
    try:
        # A stored public key can also fail to decode here -- a legacy or
        # otherwise corrupt row is not structurally different from the
        # crafted COSE keys _verify_registration already guards against,
        # and decode_credential_public_key/decoded_public_key_to_cryptography
        # can raise a raw ValueError/KeyError/IndexError on it.
        verified = verify_authentication_response(
            credential=parsed, expected_challenge=row.challenge,
            expected_rp_id=rp_id, expected_origin=expected_origin,
            credential_public_key=bytes(passkey.public_key),
            credential_current_sign_count=passkey.sign_count,
            require_user_verification=True)
    except (WebAuthnException, ValueError, KeyError, TypeError, IndexError,
            AttributeError) as exc:
        # Includes a non-increasing sign counter: possibly a cloned authenticator.
        log.warning('passkey assertion rejected for passkey %s: %s',
                    passkey.pk, type(exc).__name__)
        raise InvalidCredentials() from exc
    passkey.sign_count = verified.new_sign_count
    passkey.backed_up = verified.credential_backed_up
    passkey.last_used_at = timezone.now()
    passkey.save(update_fields=['sign_count', 'backed_up', 'last_used_at'])
    return passkey


def finish_login(challenge_id, credential):
    """Return the active user the assertion proves."""
    user = _verify_assertion(challenge_id, credential).user
    if not user.is_active:
        raise InactiveUser()
    update_last_login(None, user)
    return user


def verify_step_up(user, password=None, assertion=None):
    """Raise StepUpFailed unless the caller re-proved they hold `user`.

    Proof is the current password, or a fresh assertion (a begin_login
    challenge_id plus credential) made with one of `user`'s own passkeys.
    """
    if password is not None:
        if (isinstance(password, str) and user.has_usable_password()
                and user.check_password(password)):
            return
        raise StepUpFailed()
    if isinstance(assertion, dict):
        try:
            passkey = _verify_assertion(assertion.get('challenge_id'),
                                        assertion.get('credential'))
        except InvalidCredentials as exc:
            raise StepUpFailed() from exc
        if passkey.user_id == user.pk:
            return
    raise StepUpFailed()
