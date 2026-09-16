"""Account recovery built on Django's password reset.

Extensions: users without a usable password (passkey-only accounts) get the
reset email too; the link also dies once a passkey is added or removed;
completing any recovery revokes every API token so a lost device loses
access; and the confirm page can create a new passkey instead of setting a
password.
"""
import logging
import random
import time

from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm
# _unicode_ci_compare is a private Django helper (leading underscore --
# never part of the public API) that PasswordResetForm.get_users itself
# relies on: a case-insensitive email match that still requires the two
# strings to be Unicode-equal once case-folded, closing the "İ"/"i" style
# tricks a plain str.lower() == str.lower() comparison would fall for.
# AccountRecoveryForm.get_users below copies Django's own email-matching
# rule verbatim (everything except the has_usable_password() filter), so it
# needs the exact same helper, not a hand-rolled equivalent that could
# drift from Django's over time. It has been stable since Django 2.1, but a
# private symbol carries no deprecation guarantee -- test_recovery.py's
# test_unicode_ci_compare_import_still_available imports it directly so a
# future Django upgrade that renames or drops it fails a test loudly,
# instead of only surfacing as an ImportError the first time a user
# actually requests a password reset in production.
from django.contrib.auth.forms import _unicode_ci_compare
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.views import PasswordResetConfirmView, PasswordResetView
from django.db import OperationalError

from .account_tokens import revoke_all_tokens
from .models import PasskeyEpoch

log = logging.getLogger(__name__)
UserModel = get_user_model()


class AccountRecoveryTokenGenerator(PasswordResetTokenGenerator):
    """Reset token that is also spent once a passkey is added or removed.

    _make_hash_value defers to PasswordResetTokenGenerator's own
    implementation for everything Django already mixes in -- the password
    hash, last_login, and email -- so the token dies on any of a password
    change, a login (last_login moves), or an email change, exactly as
    Django's default token does. It then appends the user's PasskeyEpoch
    counter (passkey_service.bump_passkey_epoch), so any passkey add *or*
    delete burns the token too: see test_recovery.py's
    test_token_invalidated_by_(new_passkey|password_change|login|
    email_change) and test_token_stays_dead_after_passkey_deleted.

    A monotonic counter, not the current passkey set's newest pk, is
    deliberate: "newest pk" is state that can go back down (add a
    passkey, then delete it, and the token that add correctly killed would
    quietly come back to life), while PasskeyEpoch only ever increases.
    """
    key_salt = 'user_data.recovery.AccountRecoveryTokenGenerator'

    def _make_hash_value(self, user, timestamp):
        # A direct queryset lookup, not user.passkey_epoch (the reverse
        # OneToOne accessor): that descriptor caches a *missing* related
        # row on the instance too (Django sets the field cache to None on a
        # DoesNotExist, not just on a hit), so a `user` object that was
        # read before bump_passkey_epoch ever ran, and then reused here,
        # would keep returning the stale "no epoch yet" answer even after
        # a passkey add/delete has since created or incremented the row.
        # make_token/check_token are the exact place a single caller can
        # hold one `user` instance across both a before and an after (this
        # is what test_token_invalidated_by_new_passkey and
        # test_token_stays_dead_after_passkey_deleted pin against), so this
        # must re-query every time rather than trust any instance cache.
        epoch = PasskeyEpoch.objects.filter(user=user).values_list('value', flat=True).first()
        return ':'.join([super()._make_hash_value(user, timestamp),
                         '' if epoch is None else str(epoch)])


recovery_token_generator = AccountRecoveryTokenGenerator()


class AccountRecoveryForm(PasswordResetForm):
    def get_users(self, email):
        """Active users with this email, with or without a usable password.

        Same as PasswordResetForm.get_users, minus its
        has_usable_password() filter: dropping that one check is what lets
        a passkey-only account (an unusable password by design) recover
        through this form. The email-match rule -- an iexact filter, then
        _unicode_ci_compare -- is otherwise identical to Django's own, so
        passkey-only and password accounts are matched the same way and
        this form is no more prone to enumeration than the stock one.

        One side effect worth naming: this also hands a reset link to a
        staff/superuser account that happens to have an unusable password
        for a reason unrelated to passkeys -- e.g. one provisioned via
        createsuperuser and never given a real password -- which stock
        Django's own get_users silently excludes. This deployment has no
        such accounts today, but a future one should not assume that.
        """
        email_field = UserModel.get_email_field_name()
        users = UserModel._default_manager.filter(
            **{'%s__iexact' % email_field: email, 'is_active': True})
        return (u for u in users if _unicode_ci_compare(email, getattr(u, email_field)))


password_reset_view = PasswordResetView.as_view(
    form_class=AccountRecoveryForm, token_generator=recovery_token_generator,
    email_template_name='registration/password_reset_email.txt')


# Retryable Postgres error codes and cap, mirroring
# passkey_service._is_retryable_db_error / _MAX_RECOVERY_ATTEMPTS exactly --
# see that module for why only these two (deadlock_detected,
# serialization_failure) count as transient rather than an application bug.
_RETRYABLE_SQLSTATES = {'40P01', '40001'}
_MAX_REVOKE_ATTEMPTS = 5


def _is_retryable_db_error(exc):
    return getattr(exc.__cause__, 'sqlstate', None) in _RETRYABLE_SQLSTATES


def _revoke_tokens_after_reset(user):
    """Best-effort: revoke every API token for `user`, retrying a transient
    Postgres deadlock or serialization failure, but never letting a
    persistent failure propagate as a 500.

    Unlike passkey_service.finish_recover's transaction A -- which can
    still fail loudly, because nothing has committed yet at that point --
    by the time this runs, AccountRecoveryConfirmView.form_valid has
    already committed the new password and consumed the one-time reset
    link. Raising here would turn an already-successful password reset
    into an unhandled 500 the caller cannot retry through that same
    (now-spent) link, which is worse than a device that stays signed in a
    little longer than intended. So a retryable error gets the same
    jittered-backoff retry passkey_service._run_with_retry uses, and
    whatever survives that -- retries exhausted, or a non-retryable error
    -- is logged with log.exception and swallowed instead of raised.
    """
    for attempt in range(1, _MAX_REVOKE_ATTEMPTS + 1):
        try:
            revoke_all_tokens(user)
            return
        except OperationalError as exc:
            if attempt < _MAX_REVOKE_ATTEMPTS and _is_retryable_db_error(exc):
                log.warning('password-reset token revocation retrying after a '
                           'deadlock/serialization failure for user %s (attempt %d)',
                           user.pk, attempt)
                time.sleep(random.uniform(0.02, 0.1) * attempt)
                continue
            log.exception('password-reset token revocation failed for user %s', user.pk)
            return
        except Exception:  # anything else must not turn a completed reset into a 500
            log.exception('password-reset token revocation failed for user %s', user.pk)
            return


class AccountRecoveryConfirmView(PasswordResetConfirmView):
    token_generator = recovery_token_generator

    def get_user(self, uidb64):
        """Same as PasswordResetConfirmView.get_user, plus an is_active
        check.

        The base implementation never filters on is_active, so a link
        issued before an account was deactivated would otherwise still let
        its holder set a new password (and have the account's tokens
        revoked) on a now-disabled account. AccountRecoveryForm.get_users
        and Task 16's _recovering_user both already require an active
        user; this closes the same gap on the confirm side.
        """
        user = super().get_user(uidb64)
        return user if user is not None and user.is_active else None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['uidb64'] = self.kwargs['uidb64']
        return context

    def form_valid(self, form):
        """Set the new password, then revoke every API token.

        Calling _revoke_tokens_after_reset synchronously, right here, is
        safe: the call chain above it -- PasswordResetConfirmView.form_valid
        -> SetPasswordForm.save -> SetPasswordMixin.set_password_and_save ->
        user.set_password() + user.save() -- opens no transaction.atomic()
        block and takes no row lock of its own. So this line is not nested
        inside an outer atomic block when revoke_all_tokens (called from
        within _revoke_tokens_after_reset) opens its own
        transaction.atomic() and takes lock_user_tokens' per-user advisory
        lock; see account_tokens.lock_user_tokens's docstring for why a
        caller already holding the user row's FOR UPDATE lock and then
        reaching for that advisory lock is exactly the shape that can
        deadlock against a concurrent OAuth refresh-token rotation --
        nothing on this path creates that shape.

        A second, best-effort revoke_all_tokens call follows, after the
        first has already committed -- the same post-commit sweep
        passkey_service.finish_recover performs, for the same reason: DOT
        validates a Grant or refresh token with a plain, unlocked SELECT
        (see the account_tokens module docstring), so a request racing the
        first revoke can still mint a brand-new token that survives its
        commit untouched. This sweep is caught and logged, never raised:
        both the password change and the first revoke have already
        committed by the time it runs.

        Only API tokens (DRF + OAuth) are revoked here, not browser
        sessions on other devices -- unlike passkey recovery
        (passkey_service.finish_recover), which also calls
        delete_user_sessions. That extra step is unnecessary on this path:
        SetPasswordForm.save() calls user.set_password() unconditionally,
        even for a passkey-only account that had no password before, so
        Django's own session-auth-hash check (every request compares the
        session's stored hash against the current
        user.get_session_auth_hash(), which is derived from the password)
        already treats every session authenticated as this user as signed
        out the moment the new password takes effect -- including, unlike
        Task 16's passkey-recovery path (which deliberately preserves the
        current browser's session via keep_session_key), the very browser
        performing this reset, if it happened to be logged in as this
        account already. There is no equivalent carve-out here, and none
        is needed: this view never requires the browser making the request
        to already be authenticated as the account being recovered.
        """
        response = super().form_valid(form)
        _revoke_tokens_after_reset(form.user)
        try:
            revoke_all_tokens(form.user)
        except Exception:  # best-effort post-commit sweep; the reset has already succeeded
            log.exception('post-commit token sweep failed for user %s after password reset',
                         form.user.pk)
        return response
