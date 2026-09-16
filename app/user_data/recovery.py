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

from django.contrib.auth import get_user_model, login
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
from django.contrib.auth.views import (INTERNAL_RESET_SESSION_TOKEN, PasswordResetConfirmView,
                                       PasswordResetView)
from django.core.exceptions import ValidationError
from django.db import OperationalError
from django.http import JsonResponse
from django.utils.http import urlsafe_base64_decode
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from . import passkey_service as service
from .account_tokens import revoke_all_tokens
from .models import PasskeyEpoch
# Reused directly from passkey_service (also private there, and also
# undocumented as a public API) rather than re-implemented here: same
# SQLSTATE set, same attempt cap. Keeping one definition means a future
# change to which Postgres error codes count as transient -- or to how
# many attempts are worth making -- only has to happen in one place;
# _revoke_tokens_after_reset below keeps only what's genuinely different
# about this call site (swallowing a persistent failure instead of
# raising it) local.
from .passkey_service import _MAX_RECOVERY_ATTEMPTS, _is_retryable_db_error
from .passkey_web_views import SESSION_BACKEND, json_body

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
        #
        # This only fixes the epoch half of the hash, not the whole thing:
        # the super() call below still reads password/last_login/email off
        # this same in-memory `user` instance, with no equivalent
        # re-fetch, so those three are just as susceptible to the same
        # stale-instance hazard in principle. That is harmless in
        # practice, not by design here -- every real caller (make_token in
        # PasswordResetForm.save, check_token in
        # AccountRecoveryConfirmView.get_user's super() call) loads a
        # fresh row right before touching the token generator, so no
        # caller of this class ever actually holds a `user` object across
        # one of those three fields changing.
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


def _revoke_tokens_after_reset(user):
    """Best-effort: revoke every API token for `user`, retrying a transient
    Postgres deadlock or serialization failure (using passkey_service's own
    _is_retryable_db_error / _MAX_RECOVERY_ATTEMPTS -- see that module for
    why only deadlock_detected and serialization_failure count as
    transient), but never letting a persistent failure propagate as a 500.

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
    -- is logged with log.exception and swallowed instead of raised. That
    swallow-vs-raise choice is the one genuine difference from
    _run_with_retry; everything about *which* errors are worth a retry is
    shared with it, not duplicated.
    """
    for attempt in range(1, _MAX_RECOVERY_ATTEMPTS + 1):
        try:
            revoke_all_tokens(user)
            return
        except OperationalError as exc:
            if attempt < _MAX_RECOVERY_ATTEMPTS and _is_retryable_db_error(exc):
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


# --- Task 16: create a new passkey from a password-reset link --------------


def _recovering_user(request, uidb64):
    """The active user whose valid reset session token this session holds,
    else None.

    This is the third of three places that must require an active user --
    see AccountRecoveryForm.get_users and AccountRecoveryConfirmView.get_user
    for the other two -- so a link issued before a deactivation can never be
    used to create a passkey (and sign in) on a now-disabled account either.

    `uidb64` can be any JSON value an anonymous caller sent (a non-dict
    body, a wrong-typed field, an int, a list, ...): its type is checked
    before it is ever handed to urlsafe_base64_decode/bytes.decode, both of
    which assume text. Past that, a value that decodes cleanly as base64 but
    not to a real primary key -- non-UTF-8 bytes (UnicodeDecodeError, a
    ValueError subclass), or a non-numeric, absurdly large or negative
    string -- must still 400, never 500: Django's AutoField.to_python raises
    a plain ValueError for non-numeric text, while a huge or negative (but
    numeric) value round-trips through the ORM/Postgres as an ordinary "no
    such row" (UserModel.DoesNotExist), needing no special case at all.
    OverflowError is kept defensively alongside those, matching the same
    guard passkey ceremonies elsewhere in this codebase use for
    attacker-controlled numeric input.
    """
    if not isinstance(uidb64, str):
        return None
    try:
        user = UserModel._default_manager.get(pk=urlsafe_base64_decode(uidb64).decode())
    except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist, ValidationError):
        return None
    token = request.session.get(INTERNAL_RESET_SESSION_TOKEN)
    if not user.is_active or not recovery_token_generator.check_token(user, token):
        return None
    return user


def _invalid_link():
    return JsonResponse({'detail': _('This password reset link is invalid or has expired.')},
                        status=400)


@require_POST
@csrf_protect
def recover_passkey_begin(request):
    user = _recovering_user(request, json_body(request).get('uidb64'))
    if user is None:
        return _invalid_link()
    # begin_recover itself calls check_session_engine() first (see its own
    # docstring): a misconfigured SESSION_ENGINE must fail loudly here, so
    # it is deliberately never caught -- see recover_passkey_finish's own
    # comment on the same point for why.
    challenge_id, options = service.begin_recover(user)
    return JsonResponse({'challenge_id': challenge_id, 'options': options})


@require_POST
@csrf_protect
def recover_passkey_finish(request):
    data = json_body(request)
    user = _recovering_user(request, data.get('uidb64'))
    if user is None:
        return _invalid_link()
    # finish_recover unconditionally deletes every OTHER session belonging
    # to `user` inside its own transaction (see its docstring). Without
    # this, a recovering browser that happens to already be signed in as
    # the account being recovered would have its own session row deleted
    # out from under this very request, and the response's own session
    # save would then fail with a 400 (SessionInterrupted) once Django's
    # SessionMiddleware finds the row already gone.
    #
    # cycle_key() first -- which also defeats session fixation, the same
    # reason login_passkey's own login() call cycles the key -- so
    # keep_session_key names the *post-cycle* row, not a pre-existing key
    # an attacker might already know. keep_session_key must be exactly
    # this value, read only from request.session.session_key: NEVER from
    # `data` (the request body), which an anonymous caller fully controls
    # -- a client-supplied value there could name an arbitrary session and
    # shield it from revocation. See
    # test_passkey_recovery_ignores_client_supplied_keep_session_key.
    request.session.cycle_key()
    try:
        # finish_recover can also raise a bare OperationalError, once its
        # own internal retries (passkey_service._run_with_retry) are
        # exhausted, or ImproperlyConfigured from check_session_engine().
        # Neither is caught here, deliberately: an exhausted-retry
        # OperationalError is a genuine, rare Postgres availability
        # problem, not anything wrong with this request, so it is left to
        # surface as an unhandled 500 -- exactly how every other passkey
        # ceremony view already treats an exception outside its own typed
        # set (RegistrationFailed, InvalidCredentials, ...), rather than
        # inventing a bespoke JSON error shape just for this endpoint. The
        # reset link stays valid either way (a failed attempt here never
        # reaches the epoch bump in _store_passkey), so the caller can
        # simply retry once the transient condition clears.
        # ImproperlyConfigured must never be swallowed either: it signals
        # an operator misconfiguration (the wrong SESSION_ENGINE) that has
        # to be fixed, not something a client-facing 400 could paper over.
        service.finish_recover(user, data.get('challenge_id'), data.get('credential'),
                               data.get('name'), keep_session_key=request.session.session_key)
    except service.RegistrationFailed:
        return JsonResponse({'detail': _('Passkey registration failed.')}, status=400)
    request.session.pop(INTERNAL_RESET_SESSION_TOKEN, None)
    login(request, user, backend=SESSION_BACKEND)
    return JsonResponse({'redirect': '/account/security/'})
