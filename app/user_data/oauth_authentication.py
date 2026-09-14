# -*- coding: utf-8 -*-
"""DRF authenticator for DOT access tokens that also requires an active user."""
from collections import OrderedDict

from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import exceptions


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
