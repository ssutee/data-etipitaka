"""django-oauth-toolkit request validator: serialises OAuth token writes.

EtipitakaOAuth2Validator wraps every django-oauth-toolkit (DOT) write path
that touches a user's Grant/RefreshToken/AccessToken/IDToken rows -- token
issuance and refresh-token rotation (save_bearer_token), refresh-token
validation (validate_refresh_token, which can itself trigger reuse
protection's family revoke), and RFC 7009 /revoke_token/ (revoke_token) --
with account_tokens.lock_user_tokens(user_id), taken before DOT's own code
touches a single row.

See lock_user_tokens' own docstring for why a per-user Postgres advisory
lock, not a row-lock ordering discipline, is what actually prevents a
deadlock against passkey recovery's own revoke_all_tokens (gated by the
same lock): Django's delete collector locks AccessToken rows -- nulling
their reverse SET_NULL pointer -- before it deletes RefreshToken rows,
which is the opposite of DOT's own explicit RefreshToken-then-AccessToken
FOR UPDATE order during rotation. No amount of reordering either side's
statements can reconcile that; only serialising entry can.

Wired in via OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS'] in
etipitaka_auth/settings.py.
"""
import hashlib

from django.db import transaction
from oauth2_provider.models import get_access_token_model, get_refresh_token_model
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749 import errors

from .account_tokens import lock_user_tokens

# Bound once at import time, exactly as oauth2_validators.py itself binds
# these (its own module-level `RefreshToken = get_refresh_token_model()`),
# so `except RefreshToken.DoesNotExist` below matches the identical class
# DOT's own code raises against, including under a swapped model.
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()


class EtipitakaOAuth2Validator(OAuth2Validator):
    """Take the per-user advisory lock before every OAuth token write."""

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Lock the token's owner before issuing or rotating tokens.

        `request.user` is unset (or an AnonymousUser) for a grant type
        with no resource owner -- client_credentials is the one this
        deployment leaves enabled (see etipitaka_auth/settings.py) -- and
        there is then no per-user row to serialise against, so this just
        defers to the real implementation.

        A RefreshToken row validate_refresh_token already found and
        attached to the request can still vanish before this runs:
        oauthlib calls the two hooks as separate steps, not one locked
        unit, so a concurrent passkey recovery's revocation can commit in
        the gap between them even with this lock in place -- the lock
        closes the deadlock, not that gap (recovery's own post-commit
        sweep is what narrows this one, the same as any other unlocked
        DOT read; see the account_tokens module docstring). DOT's own
        rotation code then hits a raw RefreshToken.DoesNotExist trying to
        re-fetch the row, which must not reach the caller as an unhandled
        500: the grant genuinely is no longer valid, so oauthlib's own
        InvalidGrantError reports it as such (a 400 invalid_grant).
        """
        user = getattr(request, 'user', None)
        if user is None or not getattr(user, 'is_authenticated', False):
            return super().save_bearer_token(token, request, *args, **kwargs)
        with transaction.atomic():
            lock_user_tokens(user.pk)
            try:
                return super().save_bearer_token(token, request, *args, **kwargs)
            except RefreshToken.DoesNotExist as exc:
                raise errors.InvalidGrantError(request=request) from exc

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """Lock the refresh token's owner before validating it.

        Reuse protection (REFRESH_TOKEN_REUSE_PROTECTION) can revoke an
        entire token family from inside the base implementation, deleting
        AccessToken rows -- exactly the write this lock exists to
        serialise -- so it has to be held before super() runs, not added
        narrowly around just that branch.

        The owner is looked up the same way DOT itself does when
        validating (by the token's checksum), but without a lock: a
        plain read, safe to race, purely to learn *whose* lock to take --
        nothing here trusts it for anything beyond that, and super()
        re-reads and validates for real under the lock. No matching row
        means nothing to serialise against, so this defers to super()
        directly.
        """
        token_checksum = hashlib.sha256(refresh_token.encode('utf-8')).hexdigest()
        user_id = (RefreshToken.objects.filter(token_checksum=token_checksum)
                  .values_list('user_id', flat=True).first())
        if user_id is None:
            return super().validate_refresh_token(refresh_token, client, request,
                                                   *args, **kwargs)
        with transaction.atomic():
            lock_user_tokens(user_id)
            return super().validate_refresh_token(refresh_token, client, request,
                                                   *args, **kwargs)

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """Lock the token's owner(s) before RFC 7009 revocation.

        Mirrors the base implementation's own lookup (by checksum and
        application, preferring `token_type_hint`'s table and falling
        back to the other one) purely to learn whose row(s) to lock;
        super() repeats its own lookup and does the actual revoking. This
        almost always resolves to a single user, but every distinct one
        found is locked, in a stable (sorted) order, before super() runs,
        so two calls that happen to implicate the same two users can
        never take these two locks in opposite orders. No match at all
        (an unknown token, or a request not tied to a stored application)
        means nothing to serialise against, so this defers to super()
        directly -- which is also what makes RFC 7009's "always look like
        it succeeded" behavior (section 2.2) come from one, unmodified
        code path either way.
        """
        application_pk = getattr(request.client, 'pk', None)
        if application_pk is None:
            return super().revoke_token(token, token_type_hint, request, *args, **kwargs)
        token_checksum = hashlib.sha256(token.encode('utf-8')).hexdigest()
        token_types = {'access_token': AccessToken, 'refresh_token': RefreshToken}
        primary = token_types.get(token_type_hint, AccessToken)
        lookup = {'token_checksum': token_checksum, 'application_id': application_pk}
        user_ids = set(primary.objects.filter(**lookup).values_list('user_id', flat=True))
        if not user_ids:
            for other_type in (t for t in token_types.values() if t is not primary):
                user_ids |= set(other_type.objects.filter(**lookup)
                                .values_list('user_id', flat=True))
        user_ids.discard(None)
        if not user_ids:
            return super().revoke_token(token, token_type_hint, request, *args, **kwargs)
        with transaction.atomic():
            for user_id in sorted(user_ids):
                lock_user_tokens(user_id)
            return super().revoke_token(token, token_type_hint, request, *args, **kwargs)
