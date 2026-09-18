"""JSON API for passkeys, used by the native apps and the web pages' fetch calls.

Account endpoints accept DRF Token and Session authentication only -- never
OAuth bearer tokens -- so a read-scoped MCP connector cannot manage a
user's credentials.

Every view here -- anonymous or signed-in -- is reachable by an untrusted
caller with an arbitrary JSON body (a signed-in caller is still an
untrusted one as far as the request body goes), so `_body()` is the one
gate every view passes a request through before touching any field of it:
it forces `request.data` to be parsed (turning malformed JSON into DRF's
own 400 response) and rejects any body that isn't a JSON object
(list/string/number), so a crafted request can only ever reach a 400,
never a 500.
"""
import logging

from django.conf import settings
from django.contrib.auth import update_session_auth_hash
from django.utils.translation import gettext as _
from rest_framework import status
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes, throttle_classes)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

from . import desktop_pairing
from . import passkey_manage as manage
from . import passkey_service as service
from .auth_views import _send_verification_email

log = logging.getLogger(__name__)


class PasskeyRateThrottle(UserRateThrottle):
    """Per user when signed in, per client IP otherwise (rate: settings 'passkey').

    `rate` is declared explicitly (DRF's own SimpleRateThrottle does not
    define it as a class attribute, only ever as an instance attribute set
    inside __init__) so a test can monkeypatch the class attribute to
    exercise throttling without touching settings.
    """
    scope = 'passkey'
    rate = None


class PasskeyPasswordThrottle(UserRateThrottle):
    """Extra, tighter throttle (rate: settings 'passkey_password') for the
    two endpoints that accept a password guess: register_begin's step-up
    and password_remove.

    Applied ALONGSIDE PasskeyRateThrottle, not instead of it -- DRF checks
    every throttle in the list and 429s if any one of them trips, and this
    one is meant to trip first. Both endpoints require authentication, so
    the password oracle this closes is against a signed-in caller's own
    account (e.g. a stolen/handed-off token): a wrong guess costs nothing
    to the attacker except a slower retry, but success is persistent
    takeover -- an attacker passkey added via register_begin survives a
    password change and isn't revoked by remove_password. Legitimate use
    is one or two requests ever, so 5/min is generous, not tight.

    `rate` is declared explicitly for the same reason as PasskeyRateThrottle.rate.
    """
    scope = 'passkey_password'
    rate = None


# Account endpoints accept DRF Token and Session authentication only -- never
# OAuth bearer tokens, so a read-scoped MCP connector cannot manage a user's
# credentials (see the module docstring).
ACCOUNT_AUTHENTICATION = [TokenAuthentication, SessionAuthentication]


def _body(request):
    """The request body as a dict, or None if it isn't a JSON object.

    Accessing `request.data` is what makes DRF actually parse the body --
    every view calls this even when it has no fields to read (login_begin),
    so a malformed JSON body always surfaces as DRF's own ParseError (400)
    instead of silently succeeding.
    """
    data = request.data
    return data if isinstance(data, dict) else None


def _bad_request():
    return Response({'detail': _('Malformed request.')}, status=status.HTTP_400_BAD_REQUEST)


def _ceremony(challenge_id, options):
    return Response({'challenge_id': challenge_id, 'options': options})


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyRateThrottle])
def login_begin(request):
    if _body(request) is None:
        return _bad_request()
    return _ceremony(*service.begin_login())


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyRateThrottle])
def login_finish(request):
    data = _body(request)
    if data is None:
        return _bad_request()
    try:
        user = service.finish_login(data.get('challenge_id'), data.get('credential'))
    except service.InactiveUser:
        message = _('This account is not active. Please verify your email.')
    except service.InvalidCredentials:
        message = _('Unable to log in with provided credentials.')
    else:
        token, _created = Token.objects.get_or_create(user=user)
        return Response({'key': token.key})
    return Response({'non_field_errors': [message]}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyRateThrottle])
def signup_begin(request):
    data = _body(request)
    if data is None:
        return _bad_request()
    try:
        return _ceremony(*service.begin_signup(data.get('username'), data.get('email')))
    except service.SignupInvalid as exc:
        return Response(exc.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyRateThrottle])
def signup_finish(request):
    data = _body(request)
    if data is None:
        return _bad_request()
    try:
        user = service.finish_signup(data.get('challenge_id'), data.get('credential'),
                                     data.get('name'))
    except service.SignupInvalid as exc:
        return Response(exc.errors, status=status.HTTP_400_BAD_REQUEST)
    except service.RegistrationFailed:
        return Response({'detail': _('Passkey registration failed.')},
                        status=status.HTTP_400_BAD_REQUEST)
    # The account and its first passkey are already committed at this point:
    # a mail outage here must not turn a successful signup into a 500, since
    # the username is now taken and there is no resend endpoint to retry
    # through -- log and still report success.
    try:
        _send_verification_email(request, user)
    except Exception:
        log.exception('failed to send verification email to user %s after passkey signup',
                      user.pk)
    return Response({'detail': _('Verification e-mail sent.')}, status=status.HTTP_201_CREATED)


# --- account endpoints: signed-in callers only (Token or Session auth) -----


def _lockout():
    return Response({'detail': _('Your account must keep at least one way to sign in.')},
                    status=status.HTTP_409_CONFLICT)


def _too_many_passkeys():
    return Response({'detail': _('You have reached the maximum number of passkeys.')},
                    status=status.HTTP_409_CONFLICT)


@api_view(['POST'])
@authentication_classes(ACCOUNT_AUTHENTICATION)
@permission_classes([IsAuthenticated])
@throttle_classes([PasskeyRateThrottle, PasskeyPasswordThrottle])
def register_begin(request):
    data = _body(request)
    if data is None:
        return _bad_request()
    try:
        service.verify_step_up(request.user, password=data.get('password'),
                               assertion=data.get('step_up'))
    except service.StepUpFailed:
        return Response({'detail': _('Re-authentication failed.')},
                        status=status.HTTP_400_BAD_REQUEST)
    try:
        return _ceremony(*service.begin_register(request.user))
    except service.TooManyPasskeys:
        return _too_many_passkeys()


@api_view(['POST'])
@authentication_classes(ACCOUNT_AUTHENTICATION)
@permission_classes([IsAuthenticated])
@throttle_classes([PasskeyRateThrottle])
def register_finish(request):
    data = _body(request)
    if data is None:
        return _bad_request()
    try:
        passkey = service.finish_register(request.user, data.get('challenge_id'),
                                          data.get('credential'), data.get('name'))
    except service.TooManyPasskeys:
        return _too_many_passkeys()
    except service.RegistrationFailed:
        return Response({'detail': _('Passkey registration failed.')},
                        status=status.HTTP_400_BAD_REQUEST)
    return Response(manage.passkey_to_dict(passkey), status=status.HTTP_201_CREATED)


@api_view(['GET'])
@authentication_classes(ACCOUNT_AUTHENTICATION)
@permission_classes([IsAuthenticated])
@throttle_classes([PasskeyRateThrottle])
def passkey_list(request):
    if _body(request) is None:
        return _bad_request()
    return Response(manage.list_passkeys(request.user))


@api_view(['PATCH', 'DELETE'])
@authentication_classes(ACCOUNT_AUTHENTICATION)
@permission_classes([IsAuthenticated])
@throttle_classes([PasskeyRateThrottle])
def passkey_detail(request, passkey_id):
    data = _body(request)
    if data is None:
        return _bad_request()
    try:
        if request.method == 'DELETE':
            manage.delete_passkey(request.user, passkey_id)
            return Response(status=status.HTTP_204_NO_CONTENT)
        passkey = manage.rename_passkey(request.user, passkey_id, data.get('name'))
    except manage.NotFound:
        return Response({'detail': _('Passkey not found.')}, status=status.HTTP_404_NOT_FOUND)
    except manage.InvalidName:
        return Response({'name': [_('Enter a name for this passkey.')]},
                        status=status.HTTP_400_BAD_REQUEST)
    except manage.LockoutGuard:
        return _lockout()
    return Response(manage.passkey_to_dict(passkey))


@api_view(['POST'])
@authentication_classes(ACCOUNT_AUTHENTICATION)
@permission_classes([IsAuthenticated])
@throttle_classes([PasskeyRateThrottle, PasskeyPasswordThrottle])
def password_remove(request):
    data = _body(request)
    if data is None:
        return _bad_request()
    try:
        user = manage.remove_password(request.user, data.get('password'))
    except manage.LockoutGuard:
        return _lockout()
    except manage.WrongPassword:
        return Response({'detail': _('Re-authentication failed.')},
                        status=status.HTTP_400_BAD_REQUEST)
    if isinstance(request.successful_authenticator, SessionAuthentication):
        # The session auth hash derives from the password hash; keep this
        # browser signed in -- a Token-authenticated caller has no session
        # to touch, and request.successful_authenticator (not e.g. checking
        # for a session on the request, which a Token-authenticated request
        # still has) is what tells the two apart.
        update_session_auth_hash(request, user)
    return Response({'has_password': False})


DESKTOP_POLL_INTERVAL = 5  # seconds; the client polls no faster than this


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyRateThrottle])
def desktop_begin(request):
    """Start a desktop sign-in handshake.

    Anonymous: the caller is a desktop app that has nobody signed in yet. The
    handshake is worthless without the browser leg, where a signed-in human
    has to confirm the user code.
    """
    if _body(request) is None:
        return _bad_request()
    device_code, row = desktop_pairing.begin()
    user_code = desktop_pairing.format_user_code(row.user_code)
    return Response({
        'device_code': device_code,
        'user_code': user_code,
        'verification_url': '%s/desktop/?code=%s' % (
            settings.OAUTH_ISSUER_URL, user_code),
        'interval': DESKTOP_POLL_INTERVAL,
        'expires_in': settings.PASSKEY_DESKTOP_TTL,
    })


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([PasskeyRateThrottle])
def desktop_poll(request):
    data = _body(request)
    if data is None:
        return _bad_request()
    try:
        return Response(desktop_pairing.redeem(data.get('device_code')))
    except desktop_pairing.PairingError:
        return Response({'detail': _('This sign-in request has expired. Please try again.')},
                        status=status.HTTP_400_BAD_REQUEST)
