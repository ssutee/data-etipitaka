"""JSON API for passkeys, used by the native apps and the web pages' fetch calls.

Account endpoints accept DRF Token and Session authentication only -- never
OAuth bearer tokens -- so a read-scoped MCP connector cannot manage a
user's credentials.

Every view here is anonymous and reachable by an untrusted caller with an
arbitrary JSON body, so `_body()` is the one gate every view passes a
request through before touching any field of it: it forces `request.data`
to be parsed (turning malformed JSON into DRF's own 400 response) and
rejects any body that isn't a JSON object (list/string/number), so a
crafted request can only ever reach a 400, never a 500.
"""
import logging

from django.utils.translation import gettext as _
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes, throttle_classes)
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

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
