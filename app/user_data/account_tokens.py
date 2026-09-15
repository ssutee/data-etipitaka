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

RefreshToken goes before AccessToken for the same reason as Grant, one
level down: DOT's validate_refresh_token looks up the RefreshToken row by
checksum with a plain, unlocked SELECT
(RefreshToken.objects.filter(token_checksum=...).first(), in
oauth2_validators.py). Once this delete has committed, that lookup finds
no row at all and validation returns False outright -- but not before:
Postgres's MVCC means a plain, unlocked SELECT is never blocked by, and
never observes, another transaction's uncommitted delete, so a concurrent
refresh-grant request that reads while this transaction is still open
sees the row exactly as it was regardless of the order deletes run in
here. Deleting RefreshToken first only narrows how long the row survives
past commit; it does not stop a read that lands inside the window before
commit. Deleting AccessToken first instead would leave the refresh token
itself fully valid for even longer after commit -- SET_NULL on
RefreshToken.access_token only clears its pointer to the now-gone access
token, it does not touch the refresh token's own validity -- so the
credential a client would actually present would stay exchangeable for a
brand-new access token until RefreshToken's own delete finally runs and
commits. Orphaning the refresh token row (deleting it, not just nulling a
pointer to it) is the protection this order buys, not a side effect the
order is chosen to avoid.

IDToken is deleted last and explicitly, because none of the other three
deletions reach it on their own: it is only ever a delete *target* (via
AccessToken.id_token), never a delete source, so an IDToken row survives
untouched unless its own table is filtered too -- leaving a live OIDC
identity token behind after "revoke everything".

None of this closes the window completely, in-transaction ordering only
narrows it: DOT's unlocked reads mean a request racing this whole
function can still complete after every delete above has already run and
mint a brand-new Grant/AccessToken/RefreshToken that our own deletes never
see. Callers doing something security-sensitive with revoke_all_tokens
(passkey recovery is the current one) are expected to call it again after
their transaction commits, to sweep up whatever slipped through during it.
"""
from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.sessions.backends.db import SessionStore
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.utils import timezone
from oauth2_provider.models import (get_access_token_model, get_grant_model,
                                    get_id_token_model, get_refresh_token_model)
from rest_framework.authtoken.models import Token

_DB_SESSION_ENGINE = 'django.contrib.sessions.backends.db'

# Batch size for the session-row delete in delete_user_sessions: one
# filter(session_key__in=...).delete() per chunk rather than one row at a
# time, but still bounded so a very large match set doesn't build one
# unbounded SQL IN clause.
_SESSION_DELETE_CHUNK = 500


def lock_user_tokens(user):
    """Take FOR UPDATE on every OAuth token row belonging to `user`, in
    DOT's own write order, before anything else in this transaction takes
    a lock on the user row itself.

    Django's Postgres backend declares every FK DEFERRABLE INITIALLY
    DEFERRED, so inserting a Grant/RefreshToken/AccessToken/IDToken row
    that references `user` needs a KEY SHARE lock on that user row -- but
    only at COMMIT, not when the INSERT itself runs. django-oauth-toolkit
    3.4.1's refresh-token rotation (oauth2_validators.py
    OAuth2Validator._save_bearer_token) takes FOR UPDATE on the
    RefreshToken row being rotated first, then FOR UPDATE on any
    AccessToken row whose source_refresh_token points at it, then deletes
    that RefreshToken's own (old) AccessToken via RefreshToken.revoke() --
    all before it inserts the new AccessToken and RefreshToken rows whose
    commit finally needs the KEY SHARE lock on the user row. So a
    transaction that takes FOR UPDATE on the user row FIRST and only
    later touches a RefreshToken or AccessToken row -- which is exactly
    what finish_recover's _store_passkey used to do, taking the user
    row's lock before revoke_all_tokens ever touched a token row -- can
    deadlock against a concurrent rotation: recovery holds the user row
    and waits on a RefreshToken/AccessToken row the rotation is holding,
    while the rotation's own commit waits on the user row recovery holds.
    An attacker who keeps a refresh-token rotation loop running against
    the account being recovered can re-form that cycle on every retry.

    Calling this, in this order, before _store_passkey ever locks the
    user row removes the cycle rather than just narrowing the window a
    retry has to win: both transactions now agree on one global lock
    order -- token rows, then the user row -- so Postgres never has
    reason to abort either side with a deadlock. Grant is included even
    though the refresh_token grant type never touches it: the
    authorization_code exchange does (invalidate_authorization_code
    deletes it), and locking it here costs one more, almost always empty,
    SELECT to also cover that path. Each set is additionally ordered by
    pk, so two transactions that both need to lock the same user's rows
    -- two concurrent recoveries, say -- agree with each other on which
    row goes first too, rather than only agreeing with DOT.

    list(...values_list('pk', flat=True)) forces the SELECT to execute
    immediately -- a bare queryset is lazy and would never issue the
    locking SELECT at all if nothing here consumed it.
    """
    for model in (get_grant_model(), get_refresh_token_model(),
                 get_access_token_model(), get_id_token_model()):
        list(model.objects.select_for_update().filter(user=user)
             .order_by('pk').values_list('pk', flat=True))


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


def check_session_engine():
    """Raise ImproperlyConfigured unless SESSION_ENGINE is plain, uncached 'db'.

    delete_user_sessions needs a server-side session row it can read and
    delete directly by primary key. 'cached_db' keeps that same row, but
    also serves reads from a cache entry that a concurrent, still-open
    transaction can re-populate (from the row this process has not
    committed the deletion of yet) in the gap right after this process
    evicts it -- deployments that actually run 'cached_db' would need a
    real analysis of that race, and production here runs plain 'db', so
    this is scoped to exactly what has been verified safe rather than
    trusted to extend cleanly. Every other engine (signed_cookies, a plain
    cache with no database backing at all, ...) keeps no server-side row
    whatsoever, so there would be nothing to scan or delete -- silently
    doing nothing would leave every prior session valid, which is the
    security hole this whole mechanism exists to close, so misconfiguring
    it must fail loudly instead of quietly no-op-ing.
    """
    if settings.SESSION_ENGINE != _DB_SESSION_ENGINE:
        raise ImproperlyConfigured(
            "delete_user_sessions requires SESSION_ENGINE = %r; %r keeps no "
            "directly deletable server-side session row." %
            (_DB_SESSION_ENGINE, settings.SESSION_ENGINE))


def delete_user_sessions(user, keep_session_key=None):
    """Delete every Django session belonging to `user`, on every device.

    revoke_all_tokens only reaches API credentials. A browser session is
    not one of those, and recovery does not always change the account's
    password (a passkey-only user has none to change; a password user's
    stays exactly as it was), so Django's session-auth-hash check -- which
    only compares a hash derived from the password -- has nothing to
    invalidate a stale session with. Something has to delete the row
    itself, and this is that something, for every user alike.

    Sessions carry no per-user index, so the only way to find every
    session belonging to `user` is an O(active sessions) scan: decode
    every still-live row and check whose auth session key it carries. This
    runs once per recovery, not once per request, so the cost is
    acceptable even with a large sessions table. See check_session_engine
    for why this requires plain 'db'.

    Matching a decoded row's SESSION_KEY against `user.pk` goes through
    the user model's own primary-key field (`to_python`), the same
    coercion django.contrib.auth's own session lookup uses -- a bare
    string comparison would miss a non-canonical encoding of the same id
    (e.g. "02" for pk 2) that Django itself still authenticates.

    `keep_session_key`, when given, is never deleted even if it belongs to
    `user` -- the caller's own current session, when the recovering
    browser is itself logged in as the account being recovered.
    """
    check_session_engine()
    model = SessionStore.get_model_class()
    pk_field = user._meta.pk
    stale_keys = []
    rows = (model.objects.filter(expire_date__gt=timezone.now())
            .only('session_key', 'session_data').iterator())
    for row in rows:
        if row.session_key == keep_session_key:
            continue
        # SessionBase.decode() never raises -- a corrupt signature or an
        # undecodable payload both fall back to {} internally -- so there
        # is nothing left here for a try/except to usefully catch.
        data = SessionStore().decode(row.session_data)
        if not isinstance(data, dict):
            continue
        try:
            matched = pk_field.to_python(data.get(SESSION_KEY)) == user.pk
        except (ValidationError, TypeError, ValueError):
            continue
        if matched:
            stale_keys.append(row.session_key)
    for start in range(0, len(stale_keys), _SESSION_DELETE_CHUNK):
        chunk = stale_keys[start:start + _SESSION_DELETE_CHUNK]
        model.objects.filter(session_key__in=chunk).delete()
