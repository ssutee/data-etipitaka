# -*- coding: utf-8 -*-
"""OAuth support view: the resource-server token check used by the remote
MCP service. (The RFC 8414 metadata document is served by django-oauth-
toolkit's OAuthServerMetadataView, wired directly in urls.py.)"""
from django.http import JsonResponse
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes)
from rest_framework.permissions import IsAuthenticated

from .oauth_authentication import ActiveUserOAuth2Authentication


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
