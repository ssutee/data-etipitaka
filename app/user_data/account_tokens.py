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

The delete order above is unrelated to, and cannot substitute for,
lock_user_tokens' advisory lock (taken first, below). An earlier version
of this module claimed the order already matched django-oauth-toolkit's
own row-lock order closely enough to rule out a deadlock; that was wrong.
Django's delete collector locks AccessToken rows -- to null their reverse
SET_NULL pointer -- *before* it deletes the RefreshToken rows below,
regardless of what order these DELETE statements are written in, which is
the opposite of DOT's own explicit RefreshToken-then-AccessToken FOR
UPDATE order during a refresh-token rotation. No ordering choice made
here can fix that, because the collector's own internal order isn't
something this module chooses. See lock_user_tokens for what actually
closes it.
"""
import hashlib
import unicodedata

from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.sessions.backends.db import SessionStore
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import connection, transaction
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

# Arbitrary fixed int4, the first argument to pg_advisory_xact_lock: fixes
# the namespace this application's advisory locks live in, so a user pk
# (the second argument) can never collide with some unrelated advisory
# lock elsewhere in this codebase or a future one that reuses the pattern.
_ADVISORY_NAMESPACE = 0x70_6B

# A second, distinct namespace for lock_signup_email below -- deliberately
# not _ADVISORY_NAMESPACE, so a signup's email-derived lock key (an
# arbitrary hash) can never collide with lock_user_tokens' own user-pk keys
# in that other namespace, even though both live in the same
# pg_advisory_xact_lock keyspace.
_EMAIL_LOCK_NAMESPACE = 0x65_6D


def lock_user_tokens(user_id):
    """Take a per-user Postgres advisory lock: pg_advisory_xact_lock(namespace, user_id).

    This is the one thing that actually serialises every writer of a
    user's OAuth token rows against every other one -- not a row-lock
    ordering discipline on Grant/RefreshToken/AccessToken/IDToken, which
    cannot do this job. Django's delete collector locks AccessToken rows
    (nulling their reverse SET_NULL pointer) *before* it deletes
    RefreshToken rows in revoke_all_tokens below, regardless of DELETE
    statement order; django-oauth-toolkit's own refresh-token rotation
    takes FOR UPDATE on the RefreshToken row *before* the AccessToken row.
    Those are opposite row-lock orders that no amount of reordering this
    codebase's own statements can reconcile, since the collector's
    internal order belongs to Django, not to this module. Two
    transactions taking the same two row locks in opposite orders is a
    textbook deadlock, and it reproduced under load: recovery's revoke
    racing a live refresh-token rotation loop.

    An advisory lock sidesteps the row-lock-ordering problem entirely by
    not being a row lock on either table at all: it just serialises
    *entry*. Whichever writer -- a rotation, a revocation, a
    reuse-triggered family revoke -- takes this lock first runs its
    entire sequence of row locks and releases them (via commit) before
    the next writer takes any lock of its own, so the two sequences can
    never interleave into a cycle.

    Every writer of a user's OAuth tokens must call this, inside its own
    transaction, before it touches a single token row:
    - revoke_all_tokens below (so passkey recovery's own revocation, both
      its dedicated transaction and its post-commit sweep, and any other
      caller, are all covered automatically);
    - EtipitakaOAuth2Validator's save_bearer_token, validate_refresh_token
      and revoke_token (user_data/oauth_validators.py), django-oauth-
      toolkit's own three writers.
    Miss one and that writer is back to racing the others on raw row
    locks, with all the same ordering problems described above.

    Warning for any future caller: never call this (directly, or via
    revoke_all_tokens) while already holding the user row's own FOR
    UPDATE lock in the same transaction. That is exactly the shape of the
    original deadlock -- a transaction holding the user row and then
    reaching for a token-table lock, racing another transaction doing the
    reverse -- just with this lock substituted for the raw AccessToken/
    RefreshToken row locks. Passkey recovery's own split into transaction
    A (revoke_all_tokens, which takes this lock) and transaction B
    (_store_passkey, which takes the user row's FOR UPDATE, and never
    this lock) exists specifically so the two never nest inside one
    transaction; see finish_recover's docstring.

    Two writers of a user's OAuth tokens still bypass this lock entirely:
    `manage.py cleartokens` (DOT's own expired-token sweep) and the
    django-oauth-toolkit admin pages (a human deleting a row by hand).
    Neither is worth serialising against the request path for -- the
    first runs on a schedule, the second is a rare, deliberate action --
    so for these two the deadlock retry around recovery's own
    transactions (finish_recover's _run_with_retry) is the backstop, not
    this lock: a genuine collision is rare and, when it happens, gets
    retried rather than surfaced as a failure.

    pg_advisory_xact_lock is transaction-scoped: Postgres releases it
    automatically at COMMIT or ROLLBACK, so a caller never has to release
    it explicitly, and cannot leak it by forgetting to.

    Raises RuntimeError outside a transaction.atomic() block. Taken in
    autocommit, an xact-scoped advisory lock is released the instant the
    single implicit statement-transaction that acquired it ends -- before
    the caller's very next statement even runs -- so it would serialise
    nothing at all while looking exactly like a working lock. Failing
    loudly here is better than that.
    """
    if not connection.in_atomic_block:
        raise RuntimeError(
            'lock_user_tokens() must run inside transaction.atomic(): taken in '
            'autocommit, pg_advisory_xact_lock is released before the next '
            'statement runs and would serialise nothing.')
    with connection.cursor() as cursor:
        cursor.execute('SELECT pg_advisory_xact_lock(%s, %s)', [_ADVISORY_NAMESPACE, user_id])


def _email_lock_key(email):
    """A stable, process-independent int4 for pg_advisory_xact_lock's second
    argument, derived from `email`.

    Not Python's builtin hash(): str hashing is salted per-process
    (PYTHONHASHSEED) unless explicitly disabled, so two different web
    workers -- exactly the processes this lock exists to serialise against
    each other -- would compute two different keys for the same email and
    the lock would serialise nothing. hashlib is deterministic across
    processes and Python versions, which a lock key must be.

    `email` is normalised (NFKC, then casefolded) before hashing, matching
    django.contrib.auth.forms._unicode_ci_compare -- the exact equivalence
    relation AccountIdentitySerializer.validate_email and
    AccountRecoveryForm.get_users both already use to decide whether two
    email strings are "the same" address. Two spellings the identity check
    would treat as duplicates must take the same lock regardless of which
    one runs first, or the lock could fail to serialise the very race it
    exists to close. A hash collision between two genuinely *different*
    emails is harmless the other way: it only costs two unrelated signups a
    moment's needless serialisation against each other, never a correctness
    problem -- the actual uniqueness guarantee comes from the identity
    re-check every caller of lock_signup_email runs after taking this lock,
    not from this hash being collision-free.
    """
    normalized = unicodedata.normalize('NFKC', email).casefold()
    digest = hashlib.sha256(normalized.encode('utf-8')).digest()
    return int.from_bytes(digest[:4], 'big', signed=True)


def lock_signup_email(email):
    """Take a per-email Postgres advisory lock: pg_advisory_xact_lock(namespace, hash(email)).

    User.email carries no DB uniqueness constraint (unlike username, which
    the database itself refuses to duplicate) -- see
    AccountIdentitySerializer.validate_email -- so nothing at the database
    level stops two concurrent account-creation transactions from both
    reading "email not taken yet" and both committing a row with it. This
    lock is what actually serialises those two writers, the same way
    lock_user_tokens serialises every writer of a single user's OAuth
    tokens: taking it first, before the identity re-check that decides
    whether the email is free, means whichever caller gets there first runs
    its whole check-then-insert sequence and commits (releasing the lock)
    before the next caller's own re-check can even run -- so that second
    check always sees the first caller's row and correctly refuses.

    Every writer that can create an account with a caller-supplied email
    must call this, inside its own transaction, before re-checking whether
    that email is taken: passkey_service.finish_signup and
    RegisterSerializer.create (the two account-creation paths) both do.
    Both share this one function/namespace, which is a deliberate bonus:
    a passkey signup and a password signup racing for the same email are
    serialised against each other too, not just against their own kind.

    Same warning as lock_user_tokens: never call this while already holding
    a user row's own FOR UPDATE lock in the same transaction -- that is the
    deadlock shape lock_user_tokens' own docstring describes, just with
    this lock substituted in. Neither caller today does: both take this
    lock as the first statement of their atomic block, before the row it
    guards even exists yet, so there is no user-row lock to have taken
    first.

    Same RuntimeError-outside-atomic guard as lock_user_tokens, and for the
    same reason -- see that function's docstring.
    """
    if not connection.in_atomic_block:
        raise RuntimeError(
            'lock_signup_email() must run inside transaction.atomic(): taken in '
            'autocommit, pg_advisory_xact_lock is released before the next '
            'statement runs and would serialise nothing.')
    with connection.cursor() as cursor:
        cursor.execute('SELECT pg_advisory_xact_lock(%s, %s)',
                       [_EMAIL_LOCK_NAMESPACE, _email_lock_key(email)])


def revoke_all_tokens(user):
    """Delete every DRF and OAuth credential belonging to `user`.

    Takes lock_user_tokens(user.pk) first, inside the same transaction as
    every delete below -- see that function's docstring for why this,
    not delete-statement order, is what actually prevents a deadlock
    against django-oauth-toolkit's own writers.

    Delete order among the four OAuth tables still matters for the
    reasons the module docstring gives (closing read races against DOT's
    own unlocked SELECTs, unrelated to the deadlock lock_user_tokens
    closes) -- so do not reorder these without re-reading it: Token, then
    Grant, then RefreshToken, then AccessToken, then IDToken.
    """
    with transaction.atomic():
        lock_user_tokens(user.pk)
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
