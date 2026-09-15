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
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.db.models import F
from django.db.models.functions import Greatest
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
from .account_tokens import check_session_engine, delete_user_sessions, revoke_all_tokens
from .models import Passkey, PasskeyUserHandle, WebAuthnChallenge
from .serializers import AccountIdentitySerializer

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
# Prefix of py_webauthn 3.0.0's own message for a non-increasing sign
# counter (verify_authentication_response's "Response sign count of {n} was
# not greater than current count of {m}"). Matched by prefix, not equality,
# since the numbers are unverified at that point -- the counter check runs
# before the signature is checked.
_COUNTER_REGRESSION_PREFIX = 'Response sign count of'


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


class SignupInvalid(PasskeyError):
    """Username/email invalid or taken; `errors` maps field -> messages."""

    def __init__(self, errors):
        super().__init__(errors)
        self.errors = errors


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
    try:
        # Rendering the template can raise too (a broken template, a bad
        # config.web_origin()) -- everything from here on must stay inside
        # the same best-effort try as send_mail, so nothing after the
        # passkey is already committed can turn into an unhandled 500.
        body = render_to_string('email/passkey_added.txt', {
            'username': user.username, 'passkey_name': passkey.name,
            'security_url': config.web_origin() + '/account/security/',
            'reset_url': config.web_origin() + '/password_reset/'})
        send_mail(_('A passkey was added to your E-Tipitaka account'), body,
                  settings.DEFAULT_FROM_EMAIL, [user.email])
    except Exception:  # a mail outage must not look like a failed registration
        log.exception('failed to send passkey-added email to user %s', user.pk)


def _begin_registration(user, purpose):
    row = challenges.create(purpose, user=user)
    return row.id, _registration_options(row.challenge, user.username,
                                         _handle_for(user), _descriptors(user))


def _consume_and_verify(purpose, challenge_id, credential, user):
    """Burn a registration-shaped challenge and verify the response against it.

    Split out of _finish_registration so finish_recover can run this step
    -- which already opens and closes its own durable transaction inside
    _consume -- before opening the separate, non-durable transaction that
    has to cover both storing the new passkey and revoking every token.
    """
    row = _consume(challenge_id, purpose, user, RegistrationFailed)
    return _verify_registration(row.challenge, credential)


def _finish_registration(user, purpose, challenge_id, credential, name):
    verified = _consume_and_verify(purpose, challenge_id, credential, user)
    return _store_passkey(user, verified, credential, name)


def begin_register(user):
    """Options for adding a passkey to a signed-in account (after step-up)."""
    return _begin_registration(user, WebAuthnChallenge.REGISTER)


def finish_register(user, challenge_id, credential, name=None):
    passkey = _finish_registration(user, WebAuthnChallenge.REGISTER,
                                   challenge_id, credential, name)
    _send_passkey_added_email(user, passkey)
    return passkey


def check_password(user, password):
    """True iff `password` is `user`'s current password.

    Guards inputs Django's own check_password cannot handle safely: a
    non-str value (e.g. an int from a loosely-typed JSON body), an empty
    string, or a lone UTF-16 surrogate -- valid JSON decodes straight into
    such a str, but str.encode('utf-8') on it raises UnicodeEncodeError deep
    inside the password hasher. Public (no underscore) because
    passkey_manage.remove_password must call this too, rather than
    checking the password itself, so the two places that can prove
    possession of the password can't drift apart.
    """
    if not isinstance(password, str) or not password:
        return False
    try:
        password.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return user.has_usable_password() and user.check_password(password)


def begin_login():
    """Options for a username-less login: the authenticator picks the account."""
    row = challenges.create(WebAuthnChallenge.LOGIN)
    return row.id, _options_json(generate_authentication_options(
        rp_id=config.rp_id(), challenge=row.challenge,
        timeout=settings.PASSKEY_CHALLENGE_TTL * 1000,
        user_verification=UserVerificationRequirement.REQUIRED))


def _log_assertion_failure(exc, passkey, parsed, challenge, rp_id, expected_origin):
    """Log a rejected assertion.

    A non-increasing sign counter can mean a cloned authenticator and is
    worth an operator's attention -- but py_webauthn checks the counter
    before the signature, so a forged assertion (a different key, the
    victim's credential id and user handle, and a low counter) trips the
    very same message without the signature ever being checked, let alone
    proving who signed it. So WARNING is only logged once the signature is
    independently confirmed genuine, by re-running verification with
    credential_current_sign_count=0 so the counter check cannot fail a
    second time; that re-verify is wrapped in the same wide except tuple as
    the first, since a corrupt stored key could still make it raise too.
    Once the signature is confirmed, the counter values in `exc` are known
    genuine (they are part of the signed authenticatorData) and safe to
    log. Every other outcome -- including a re-verify that itself fails --
    is routine and gets INFO with just the exception's type name, never a
    message that could otherwise embed attacker-chosen numbers.
    """
    if isinstance(exc, WebAuthnException) and str(exc).startswith(_COUNTER_REGRESSION_PREFIX):
        try:
            verify_authentication_response(
                credential=parsed, expected_challenge=challenge,
                expected_rp_id=rp_id, expected_origin=expected_origin,
                credential_public_key=bytes(passkey.public_key),
                credential_current_sign_count=0, require_user_verification=True)
        except (WebAuthnException, ValueError, KeyError, TypeError, IndexError,
                AttributeError):
            pass
        else:
            log.warning('passkey assertion rejected for passkey %s: possible cloned '
                        'authenticator (%s)', passkey.pk, exc)
            return
    log.info('passkey assertion rejected for passkey %s: %s',
             passkey.pk, type(exc).__name__)


def _verify_assertion(challenge_id, credential, owner=None):
    """Verify a login assertion and return its Passkey with usage recorded.

    `owner`, when given, additionally requires the assertion to be made
    with a passkey belonging to that user (step-up's own use) -- checked
    before the assertion is cryptographically verified or its usage is
    recorded, so a step-up attempt with someone else's passkey never
    touches that passkey's counter or last_used_at.
    """
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
    if owner is not None and passkey.user_id != owner.pk:
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
        _log_assertion_failure(exc, passkey, parsed, row.challenge, rp_id, expected_origin)
        raise InvalidCredentials() from exc
    # A conditional update, not passkey.save(update_fields=...): two
    # concurrent assertions must not let whichever reaches here later lower
    # a counter the other already advanced, and if the row was deleted
    # between the lookup above and here (e.g. a concurrent passkey
    # removal), save(update_fields=...) would raise DatabaseError (a 500)
    # instead of the clean InvalidCredentials a vanished credential
    # deserves -- update() instead affects zero rows and we can tell.
    now = timezone.now()
    updated = Passkey.objects.filter(pk=passkey.pk).update(
        sign_count=Greatest(F('sign_count'), verified.new_sign_count),
        backed_up=verified.credential_backed_up, last_used_at=now)
    if not updated:
        raise InvalidCredentials()
    # Set the fields locally rather than refresh_from_db(): the row could
    # be deleted between the update above and a refresh, which would raise
    # Passkey.DoesNotExist instead of the InvalidCredentials this function
    # promises. Greatest() is mirrored here with max() so the in-memory
    # value matches what was actually written.
    passkey.sign_count = max(passkey.sign_count, verified.new_sign_count)
    passkey.backed_up = verified.credential_backed_up
    passkey.last_used_at = now
    return passkey


def finish_login(challenge_id, credential):
    """Return the active user the assertion proves."""
    user = _verify_assertion(challenge_id, credential).user
    if not user.is_active:
        raise InactiveUser()
    # A plain queryset update, not update_last_login()'s user.save(): if the
    # user row were ever deleted concurrently, save(update_fields=...)
    # would raise DatabaseError instead of just not recording the login.
    # _verify_assertion already returned this passkey/user without
    # re-reading either row, so nothing here re-reads the passkey either.
    now = timezone.now()
    get_user_model().objects.filter(pk=user.pk).update(last_login=now)
    user.last_login = now
    return user


def verify_step_up(user, password=None, assertion=None):
    """Raise StepUpFailed unless the caller re-proved they hold `user`.

    Proof is the current password, or a fresh assertion (a begin_login
    challenge_id plus credential) made with one of `user`'s own passkeys.
    A password takes precedence when both are given: a wrong password is
    not a chance to fall back to trying the assertion instead.
    """
    if password is not None:
        if check_password(user, password):
            return
        raise StepUpFailed()
    if isinstance(assertion, dict):
        try:
            _verify_assertion(assertion.get('challenge_id'), assertion.get('credential'),
                              owner=user)
        except InvalidCredentials as exc:
            raise StepUpFailed() from exc
        return
    raise StepUpFailed()


def _plain_errors(errors):
    return {field: [str(message) for message in messages]
            for field, messages in errors.items()}


def begin_signup(username, email):
    """Validate a new account's identity and return registration options.

    No User row exists until finish_signup verifies the passkey.
    """
    serializer = AccountIdentitySerializer(data={'username': username, 'email': email})
    if not serializer.is_valid():
        raise SignupInvalid(_plain_errors(serializer.errors))
    data = serializer.validated_data
    handle = secrets.token_bytes(32)
    row = challenges.create(WebAuthnChallenge.SIGNUP, payload={
        'username': data['username'], 'email': data['email'],
        'handle': bytes_to_base64url(handle)})
    return row.id, _registration_options(row.challenge, data['username'], handle, [])


def finish_signup(challenge_id, credential, name=None):
    """Create the inactive, passwordless account with its first passkey.

    The caller sends the verification email. Ordering matters: the
    challenge is consumed and the response cryptographically verified
    before either the identity is re-checked or any row is written, so a
    crafted or replayed request never reaches user creation. The identity
    is re-validated here (not just in begin_signup) because the username or
    email may have been taken by someone else in between.
    """
    row = _consume(challenge_id, WebAuthnChallenge.SIGNUP, None, RegistrationFailed)
    verified = _verify_registration(row.challenge, credential)
    payload = row.payload
    serializer = AccountIdentitySerializer(data={'username': payload['username'],
                                                 'email': payload['email']})
    if not serializer.is_valid():  # taken since begin_signup
        raise SignupInvalid(_plain_errors(serializer.errors))
    try:
        with transaction.atomic():
            user = get_user_model()(username=payload['username'], email=payload['email'],
                                    is_active=False)
            user.set_unusable_password()
            user.save()
            PasskeyUserHandle.objects.create(user=user,
                                             handle=base64url_to_bytes(payload['handle']))
            _store_passkey(user, verified, credential, name)
    except IntegrityError as exc:  # username taken between the check and the insert
        raise SignupInvalid({'username': [_('A user with that username already exists.')]}) from exc
    return user


def begin_recover(user):
    """Options for creating a passkey from a valid account-recovery session.

    check_session_engine() first: finish_recover cannot complete recovery
    without a working delete_user_sessions, so a misconfigured
    SESSION_ENGINE should fail before a one-time recovery challenge is
    even created, not after the caller has already spent it.
    """
    check_session_engine()
    return _begin_registration(user, WebAuthnChallenge.RECOVER)


def finish_recover(user, challenge_id, credential, name=None, *, keep_session_key=None):
    """Store the new passkey, revoke every token, and sign every other
    browser session out.

    check_session_engine() runs before anything else, including consuming
    the challenge: delete_user_sessions needs it later, inside the atomic
    block below, and failing before _consume_and_verify means a
    misconfigured SESSION_ENGINE never burns the caller's one-time
    challenge for a recovery that couldn't have completed anyway.

    Consuming the challenge and verifying the response happen next,
    exactly like every other ceremony, and outside the transaction below
    -- _consume_and_verify already opened and closed its own durable
    transaction inside _consume, and a durable atomic block can never nest
    inside a regular one.

    Storing the passkey, revoking every token, and deleting every session
    then happen together in one atomic block: a password-reset-driven
    recovery is meant for an account an attacker may currently be living
    inside, so a failure partway through any of the three must not leave
    the account half-recovered -- a passkey added but the old tokens or
    sessions still live, for instance.

    revoke_all_tokens runs a second time after that transaction commits.
    DOT validates a Grant or a refresh token with a plain, unlocked SELECT
    (see the account_tokens module docstring), so a request racing this
    whole function can still mint a brand-new token at any point during
    the transaction and have that mint survive the commit untouched --
    the in-transaction revoke only narrows this window, it cannot close
    it. This second sweep is best-effort, like the email below: recovery
    has already committed by the time it runs, so a sweep failure is
    logged, not raised back at whoever is waiting on this recovery to
    succeed.

    The email is sent last, after both revoke passes, so a failure in
    either one never sends a "passkey added" notice for a recovery that
    has not actually finished revoking everything yet.

    Task 16: the recovery view should call request.session.cycle_key()
    once it has verified the reset token (before calling this function),
    then pass keep_session_key=request.session.session_key -- only ever
    that value, read from the session actually driving the request, never
    anything client-supplied -- so the browser doing the recovering is
    not signed out of its own, freshly-cycled session.
    """
    check_session_engine()
    verified = _consume_and_verify(WebAuthnChallenge.RECOVER, challenge_id, credential, user)
    with transaction.atomic():
        passkey = _store_passkey(user, verified, credential, name)
        revoke_all_tokens(user)
        delete_user_sessions(user, keep_session_key=keep_session_key)
    try:
        revoke_all_tokens(user)
    except Exception:  # recovery already committed; a sweep failure must not look like one
        log.exception('post-commit token sweep failed for user %s during recovery', user.pk)
    _send_passkey_added_email(user, passkey)
    return passkey
