# -*- coding: utf-8 -*-
"""OAuth support view: the resource-server token check used by the remote
MCP service. (The RFC 8414 metadata document is served by django-oauth-
toolkit's OAuthServerMetadataView, wired directly in urls.py.)"""
from collections import OrderedDict

from django.http import JsonResponse
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import exceptions
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes)
from rest_framework.permissions import IsAuthenticated


class ActiveUserOAuth2Authentication(OAuth2Authentication):
    """OAuth2Authentication that also rejects tokens not bound to an active user.

    django-oauth-toolkit validates the token, not the account: a user set
    inactive after consenting would otherwise keep verifying (and refreshing)
    for the refresh-token lifetime, and a client-credentials token (its
    AccessToken.user is None) has no account to check at all. DRF's
    Token/Session authenticators already reject inactive users; this makes
    the OAuth path consistent for both cases.
    """

    def authenticate(self, request):
        result = super().authenticate(request)
        user = result[0] if result is not None else None
        if result is not None and (user is None or not user.is_active):
            request.oauth2_error = OrderedDict([
                ('error', 'invalid_token'),
                ('error_description',
                 'The access token is not bound to an active user.'),
            ])
            raise exceptions.AuthenticationFailed(
                'The access token is not bound to an active user.')
        return result


@api_view(['GET'])
@authentication_classes((ActiveUserOAuth2Authentication,))
@permission_classes((IsAuthenticated,))
def verify(request):
    """Token check for the MCP resource server.

    Reports the token's scopes but does NOT enforce them: the MCP SDK enforces
    its required scope (answering 403 insufficient_scope) and /api/content/*
    enforces it again independently. A user-less token (client-credentials
    grant) is rejected as invalid_token (401); the consumer treats any
    non-200 as invalid.
    """
    tok = request.auth  # oauth2_provider.models.AccessToken
    resp = JsonResponse({
        'active': True,
        'username': request.user.username,
        'user_id': request.user.pk,
        'scopes': tok.scope.split(),
        'expires_at': int(tok.expires.timestamp()),
        # Always a string: the MCP side builds an AccessToken(client_id=str).
        'client_id': tok.application.client_id if tok.application else '',
    })
    resp['Cache-Control'] = 'no-store'
    return resp
