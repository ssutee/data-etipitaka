"""Revoke every API credential a user holds: the DRF token and OAuth tokens.

Deletion order does not matter for referential integrity here. Every
django-oauth-toolkit foreign key between these four models is either
SET_NULL (AccessToken.source_refresh_token, RefreshToken.access_token --
deleting the referenced row just clears the pointer, never blocks the
delete) or CASCADE from the *referenced* side onto the row holding the FK
(AccessToken.id_token -> IDToken: deleting an IDToken cascades onto the
AccessToken that points at it). Django's ORM delete collector resolves all
of that per call regardless of which of these four deletes runs first, so
no ordering here can raise IntegrityError.

IDToken is deleted explicitly because none of the other three deletions
reach it on their own: it is only ever a delete *target* (via
AccessToken.id_token), never a delete source, so an IDToken row survives
untouched unless its own table is filtered too -- leaving a live OIDC
identity token behind after "revoke everything".
"""
from oauth2_provider.models import (get_access_token_model, get_grant_model,
                                    get_id_token_model, get_refresh_token_model)
from rest_framework.authtoken.models import Token


def revoke_all_tokens(user):
    """Delete every DRF and OAuth credential belonging to `user`."""
    Token.objects.filter(user=user).delete()
    get_refresh_token_model().objects.filter(user=user).delete()
    get_access_token_model().objects.filter(user=user).delete()
    get_grant_model().objects.filter(user=user).delete()
    get_id_token_model().objects.filter(user=user).delete()
