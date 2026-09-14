# -*- coding: utf-8 -*-
from rest_framework.permissions import BasePermission

SCOPE = 'etipitaka:read'


class ScopedOrAuthenticated(BasePermission):
    """OAuth access tokens must carry `etipitaka:read`; DRF tokens and
    sessions only need to be authenticated (unchanged behaviour).

    django-oauth-toolkit's TokenHasScope cannot be used directly: it asserts
    when the request was authenticated by anything other than OAuth2, which
    would break the existing DRF-token clients.
    """

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        token = request.auth
        if hasattr(token, 'scope'):  # oauth2_provider.models.AccessToken
            return token.is_valid([SCOPE])
        return True
