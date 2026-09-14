# -*- coding: utf-8 -*-
"""OAuth support view: the resource-server token check used by the remote
MCP service. (The RFC 8414 metadata document is served by django-oauth-
toolkit's OAuthServerMetadataView, wired directly in urls.py.)"""
from django.http import JsonResponse
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes)
from rest_framework.permissions import IsAuthenticated


@api_view(['GET'])
@authentication_classes((OAuth2Authentication,))
@permission_classes((IsAuthenticated,))
def verify(request):
    """Token check for the MCP resource server.

    Reports the token's scopes but does NOT enforce them: the MCP SDK enforces
    its required scope (answering 403 insufficient_scope) and /api/content/*
    enforces it again independently.
    """
    tok = request.auth  # oauth2_provider.models.AccessToken
    return JsonResponse({
        'active': True,
        'username': request.user.username,
        'user_id': request.user.pk,
        'scopes': tok.scope.split(),
        'expires_at': int(tok.expires.timestamp()),
        'client_id': tok.application.client_id if tok.application else None,
    })
