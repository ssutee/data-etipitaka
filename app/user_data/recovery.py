"""Account recovery built on Django's password reset.

Extensions: users without a usable password (passkey-only accounts) get the
reset email too; the link also dies once a passkey is added; completing any
recovery revokes every API token so a lost device loses access; and the
confirm page can create a new passkey instead of setting a password.
"""
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
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.views import PasswordResetConfirmView, PasswordResetView

from .account_tokens import revoke_all_tokens


class AccountRecoveryTokenGenerator(PasswordResetTokenGenerator):
    """Reset token that is also spent once a passkey is added.

    _make_hash_value defers to PasswordResetTokenGenerator's own
    implementation for everything Django already mixes in -- the password
    hash, last_login, and email -- so the token dies on any of a password
    change, a login (last_login moves), or an email change, exactly as
    Django's default token does. It then appends the newest passkey's pk,
    so a new passkey burns the token too: see test_recovery.py's
    test_token_invalidated_by_(new_passkey|password_change|login|
    email_change) for each case pinned individually.
    """
    key_salt = 'user_data.recovery.AccountRecoveryTokenGenerator'

    def _make_hash_value(self, user, timestamp):
        newest = user.passkeys.order_by('-pk').values_list('pk', flat=True).first()
        return super()._make_hash_value(user, timestamp) + str(newest or '')


recovery_token_generator = AccountRecoveryTokenGenerator()


class AccountRecoveryForm(PasswordResetForm):
    def get_users(self, email):
        """Active users with this email, with or without a usable password.

        Copied from PasswordResetForm.get_users with exactly one change:
        the has_usable_password() filter is dropped, so a passkey-only
        account (an unusable password by design, not an accident) is still
        offered recovery. The email-match rule itself -- iexact filter,
        then _unicode_ci_compare -- stays identical to Django's own so
        passkey-only and password accounts are matched the same way, and
        this form is no more (or less) prone to enumeration than the
        stock one.
        """
        email_field = User.get_email_field_name()
        users = User._default_manager.filter(
            **{'%s__iexact' % email_field: email, 'is_active': True})
        return (u for u in users if _unicode_ci_compare(email, getattr(u, email_field)))


password_reset_view = PasswordResetView.as_view(
    form_class=AccountRecoveryForm, token_generator=recovery_token_generator,
    email_template_name='registration/password_reset_email.txt')


class AccountRecoveryConfirmView(PasswordResetConfirmView):
    token_generator = recovery_token_generator

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['uidb64'] = self.kwargs['uidb64']
        return context

    def form_valid(self, form):
        """Set the new password, then revoke every API token.

        Calling revoke_all_tokens synchronously, right here, is safe: the
        call chain above it -- PasswordResetConfirmView.form_valid ->
        SetPasswordForm.save -> SetPasswordMixin.set_password_and_save ->
        user.set_password() + user.save() -- opens no transaction.atomic()
        block and takes no row lock of its own. So this line is not nested
        inside an outer atomic block when revoke_all_tokens opens its own
        transaction.atomic() and takes lock_user_tokens' per-user advisory
        lock; see account_tokens.lock_user_tokens's docstring for why a
        caller already holding the user row's FOR UPDATE lock and then
        reaching for that advisory lock is exactly the shape that can
        deadlock against a concurrent OAuth refresh-token rotation --
        nothing on this path creates that shape.

        Only API tokens (DRF + OAuth) are revoked here, not browser
        sessions on other devices -- unlike passkey recovery
        (passkey_service.finish_recover), which also calls
        delete_user_sessions. That extra step is unnecessary on this path:
        SetPasswordForm.save() calls user.set_password() unconditionally,
        even for a passkey-only account that had no password before, so
        Django's own session-auth-hash check (every request compares the
        session's stored hash against the current
        user.get_session_auth_hash(), which is derived from the password)
        already treats every other browser's session as signed out the
        moment this new password takes effect. Scanning and deleting
        session rows here would be redundant work, not an extra safety
        net.
        """
        response = super().form_valid(form)
        revoke_all_tokens(form.user)
        return response
