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
    """OAuth2Authentication that also rejects tokens of deactivated users.

    django-oauth-toolkit validates the token, not the account: a user set
    inactive after consenting would otherwise keep verifying (and refreshing)
    for the refresh-token lifetime. DRF's Token/Session authenticators already
    reject inactive users; this makes the OAuth path consistent.
    """

    def authenticate(self, request):
        result = super().authenticate(request)
        if result is not None and not result[0].is_active:
            request.oauth2_error = OrderedDict([
                ('error', 'invalid_token'),
                ('error_description', 'User inactive or deleted.'),
            ])
            raise exceptions.AuthenticationFailed('User inactive or deleted.')
        return result


@api_view(['GET'])
@authentication_classes((ActiveUserOAuth2Authentication,))
@permission_classes((IsAuthenticated,))
def verify(request):
    """Token check for the MCP resource server.

    Reports the token's scopes but does NOT enforce them: the MCP SDK enforces
    its required scope (answering 403 insufficient_scope) and /api/content/*
    enforces it again independently. A user-less token (client-credentials
    grant) is rejected by IsAuthenticated with 403; the consumer treats any
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
