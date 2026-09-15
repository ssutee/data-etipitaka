"""Revoke every API credential a user holds: the DRF token and OAuth tokens.

None of django-oauth-toolkit's FKs between these models can turn this into
an IntegrityError -- AccessToken.source_refresh_token and
RefreshToken.access_token are both SET_NULL, and AccessToken.id_token is
CASCADE from the *referenced* (IDToken) side, so Django's delete collector
never has a NOT NULL or PROTECT constraint to trip over regardless of call
order. But order is NOT irrelevant: it decides how much of a live,
concurrent request this revocation can still race.

Grant goes first, before RefreshToken and AccessToken, to close the
authorization-code exchange race: DOT's validate_code reads the Grant row
without taking a lock, so a code exchange racing this call can still slip
its read in before the Grant disappears. Deleting the Grant first, and as
early as possible, both shrinks that read window and -- because our own
DELETE holds the row lock for the rest of this transaction -- makes a
concurrent exchange trying to consume the same grant block on that lock
and land on invalid_grant once we commit and the row is simply gone,
instead of racing to mint a fresh access/refresh token pair after we've
already moved on to revoking those.

RefreshToken goes before AccessToken for the same reason in miniature: if
a refresh-token rotation is in flight, deleting the access token first
would let RefreshToken.access_token (SET_NULL) silently orphan a
concurrently-created refresh token by nulling out the access token it was
just bound to; deleting refresh tokens first instead means any refresh
token that rotation creates after our delete has already run remains
directly deletable (by table, not by a since-vanished FK), and DOT refuses
to honor an orphaned refresh token during that same window regardless.

IDToken is deleted last and explicitly, because none of the other three
deletions reach it on their own: it is only ever a delete *target* (via
AccessToken.id_token), never a delete source, so an IDToken row survives
untouched unless its own table is filtered too -- leaving a live OIDC
identity token behind after "revoke everything".
"""
from importlib import import_module

from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from oauth2_provider.models import (get_access_token_model, get_grant_model,
                                    get_id_token_model, get_refresh_token_model)
from rest_framework.authtoken.models import Token


def revoke_all_tokens(user):
    """Delete every DRF and OAuth credential belonging to `user`.

    Order matters -- see the module docstring -- so do not reorder these
    without re-reading it: Token, then Grant, then RefreshToken, then
    AccessToken, then IDToken.
    """
    Token.objects.filter(user=user).delete()
    get_grant_model().objects.filter(user=user).delete()
    get_refresh_token_model().objects.filter(user=user).delete()
    get_access_token_model().objects.filter(user=user).delete()
    get_id_token_model().objects.filter(user=user).delete()


def delete_user_sessions(user, keep_session_key=None):
    """Delete every Django session belonging to `user`, on every device.

    revoke_all_tokens only reaches API credentials. A browser session is
    not one of those, and recovery does not always change the account's
    password (a passkey-only user has none to change; a password user's
    stays exactly as it was), so Django's session-auth-hash check -- which
    only compares a hash derived from the password -- has nothing to
    invalidate a stale session with. Something has to delete the row
    itself, and this is that something.

    Sessions carry no per-user index, so the only way to find every
    session belonging to `user` is an O(active sessions) scan: decode
    every still-live row and check whose auth session key it carries. This
    runs once per recovery, not once per request, so the cost is
    acceptable even with a large sessions table.

    Requires a database-backed SESSION_ENGINE ('db', or its cached
    variant 'cached_db' -- both expose get_model_class()). A signed-cookie
    or plain-cache engine keeps no server-side row to scan or delete, so
    silently doing nothing here would leave every prior session valid --
    the exact security hole this function exists to close -- so that
    configuration raises loudly instead of a quiet, wrong no-op.

    `keep_session_key`, when given, is never deleted even if it belongs to
    `user` -- the caller's own current session, when the recovering
    browser is itself logged in as the account being recovered.
    """
    store = import_module(settings.SESSION_ENGINE).SessionStore
    if not hasattr(store, 'get_model_class'):
        raise ImproperlyConfigured(
            "delete_user_sessions requires a database-backed SESSION_ENGINE "
            "('db' or 'cached_db'); %r keeps no server-side session row to "
            "scan or delete." % settings.SESSION_ENGINE)
    model = store.get_model_class()
    target = str(user.pk)
    rows = (model.objects.filter(expire_date__gt=timezone.now())
            .only('session_key', 'session_data').iterator())
    for row in rows:
        if row.session_key == keep_session_key:
            continue
        try:
            data = store().decode(row.session_data)
        except Exception:  # corrupt session data must never abort the scan
            continue
        if str(data.get(SESSION_KEY)) == target:
            # Go through the store, not model.objects.filter(...).delete():
            # cached_db keeps a cache entry per session_key that only the
            # store's own delete() knows to evict.
            store(session_key=row.session_key).delete()
