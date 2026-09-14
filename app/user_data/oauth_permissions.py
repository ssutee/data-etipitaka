# -*- coding: utf-8 -*-
from rest_framework import exceptions
from rest_framework.permissions import BasePermission

SCOPE = 'etipitaka:read'


class ScopedOrAuthenticated(BasePermission):
    """OAuth access tokens must carry `etipitaka:read`; DRF tokens and
    sessions only need to be authenticated (unchanged behaviour).

    django-oauth-toolkit's IsAuthenticatedOrTokenHasScope would do the same
    job, but it reads `required_scopes` off the view class, which
    function-based `api_view` views do not carry; with one fixed scope a
    small explicit permission is clearer.
    """

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        token = request.auth
        if not hasattr(token, 'scope'):  # DRF Token or session
            return True
        if token.is_valid([SCOPE]):  # oauth2_provider.models.AccessToken
            return True
        exc = exceptions.PermissionDenied(
            'The access token does not carry the %s scope.' % SCOPE)
        exc.auth_header = ('Bearer realm="api",error="insufficient_scope",'
                           'scope="%s"' % SCOPE)
        raise exc
