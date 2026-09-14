# -*- coding: utf-8 -*-
"""RFC 8707 audience check for access tokens presented to this service."""
from django.conf import settings
from oauth2_provider.oauth2_validators import validate_resource_as_url_prefix


def validate_mcp_audience(request_uri, audiences):
    """Accept tokens bound to the remote MCP endpoint on its backing APIs.

    MCP clients (ChatGPT, for one) send `resource=<MCP URL>` when authorizing,
    so the token they hold is audience-bound to that URL. The MCP service then
    forwards the token to /api/oauth/verify/, /api/content/* and
    /rest-auth/user/ over the internal network, where django-oauth-toolkit's
    default check compares the audience with the request URI
    (http://web:8000/...) and rejects every such token. Those endpoints are the
    MCP resource's backend, so its audience is accepted here by exact match;
    any other audience still falls back to the default prefix check.
    """
    mcp = settings.OAUTH_MCP_RESOURCE_URL
    if any(isinstance(aud, str) and aud.rstrip('/') == mcp for aud in audiences):
        return True
    return validate_resource_as_url_prefix(request_uri, audiences)
