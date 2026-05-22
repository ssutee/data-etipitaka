from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.http import HttpResponseRedirect
from django.template.loader import render_to_string
from django.utils.translation import gettext as _

from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes, throttle_classes)
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle

from .serializers import RegisterSerializer, LoginSerializer


class LoginRateThrottle(AnonRateThrottle):
    """Throttles the token-login endpoint by client IP (rate: settings 'login')."""
    scope = 'login'


def _signer():
    return TimestampSigner(salt=settings.EMAIL_VERIFICATION_SALT)


def _send_verification_email(request, user):
    token = _signer().sign(str(user.pk))
    verify_url = request.build_absolute_uri(
        settings.EMAIL_VERIFICATION_URL + token + '/')
    body = render_to_string('email/verify_email.txt',
                            {'username': user.username, 'verify_url': verify_url})
    send_mail(_('Confirm your E-Tipitaka account'), body,
              settings.DEFAULT_FROM_EMAIL, [user.email])


def _activate_from_token(token):
    """Return the activated user, or None if the token is invalid/expired."""
    try:
        pk = _signer().unsign(token, max_age=settings.EMAIL_VERIFICATION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    try:
        user = User.objects.get(pk=int(pk))
    except User.DoesNotExist:
        return None
    if not user.is_active:
        user.is_active = True
        user.save(update_fields=['is_active'])
    return user


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
@throttle_classes([LoginRateThrottle])
def rest_login(request):
    serializer = LoginSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    user = serializer.validated_data['user']
    token, _ = Token.objects.get_or_create(user=user)
    return Response({'key': token.key})


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def rest_logout(request):
    Token.objects.filter(user=request.user).delete()
    return Response({'detail': _('Successfully logged out.')})


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def rest_user_details(request):
    user = request.user
    return Response({'pk': user.pk, 'username': user.username, 'email': user.email})


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def rest_register(request):
    serializer = RegisterSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    user = serializer.save()
    _send_verification_email(request, user)
    return Response({'detail': _('Verification e-mail sent.')},
                    status=status.HTTP_201_CREATED)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def rest_verify_email(request):
    user = _activate_from_token(request.data.get('key', ''))
    if user is None:
        return Response({'detail': _('Invalid or expired token.')},
                        status=status.HTTP_400_BAD_REQUEST)
    return Response({'detail': 'ok'})


@api_view(['GET'])
@authentication_classes([])
@permission_classes([])
def account_confirm_email(request, key):
    """Landing page for the link in the verification email."""
    user = _activate_from_token(key)
    if user is None:
        return HttpResponseRedirect('/login/?email=invalid')
    return HttpResponseRedirect('/login/?email=confirm')
