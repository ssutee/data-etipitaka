# -*- coding: utf-8 -*-
"""OAuth support views: RFC 8414 server metadata (Task 3 adds the
resource-server token check used by the remote MCP service)."""
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET

SCOPE = 'etipitaka:read'


@require_GET
def as_metadata(request):
    """RFC 8414 Authorization Server Metadata. The issuer is the site root."""
    base = settings.OAUTH_ISSUER_URL.rstrip('/')
    return JsonResponse({
        'issuer': base,
        'authorization_endpoint': base + '/o/authorize/',
        'token_endpoint': base + '/o/token/',
        'registration_endpoint': base + '/o/register/',
        'revocation_endpoint': base + '/o/revoke_token/',
        'scopes_supported': [SCOPE],
        'response_types_supported': ['code'],
        'grant_types_supported': ['authorization_code', 'refresh_token'],
        'code_challenge_methods_supported': ['S256'],
        'token_endpoint_auth_methods_supported': ['none', 'client_secret_post'],
    })
