"""Delete accounts permanently stranded by passkey signup.

passkey_views.signup_finish creates the User row and its first passkey
together (see passkey_service.finish_signup), then best-effort sends the
verification email -- and deliberately still reports success even when
that send fails (see signup_finish's own docstring), since the username is
already taken by then and there is no resend endpoint to retry through. If
the mail never arrives, or the recipient just never clicks the link, the
account is stuck forever: it's inactive with an unusable password
(passkey-only -- there is no password to reset), recovery.py excludes
inactive users by design, both login paths return "account not active" for
it, and a second signup attempt collides on both the username and the
email (AccountIdentitySerializer / begin_signup check both for
uniqueness) -- so nobody, including the person who meant to sign up, can
ever use that username or email again.

Conservative by design -- a candidate is deleted only if ALL of:
  - is_active is False (never completed verification, by any path);
  - last_login is NULL (no login history at all -- redundant with the
    above today, since an inactive user cannot authenticate through any
    backend this project configures, but kept as an explicit belt-and-
    suspenders guard rather than relying on that staying true forever);
  - password starts with '!' (Django's UNUSABLE_PASSWORD_PREFIX --
    make_password(None) always produces one, and User.password is a
    non-nullable column, so this is the exact SQL-pushdown equivalent of
    `not user.has_usable_password()`; see is_password_usable). Excludes
    every *password* signup (rest_register) even though it can go
    stranded the same way: a password account might still be retried by
    other means, and deleting one is riskier, so this command's scope is
    strictly the passkey-only case that truly has no recovery path at
    all;
  - date_joined is at least EMAIL_VERIFICATION_MAX_AGE old -- the same TTL
    auth_views._activate_from_token already enforces on the signed token,
    so this only ever deletes a row whose verification link has
    unconditionally expired already; a fresh signup is left alone even if
    every other condition already matches;
  - has at least one passkey (passkeys__isnull=False) -- this command's
    whole justification is "passkey-only signup with no recovery path",
    so an inactive account that never even got that far (no password AND
    no passkey -- shouldn't normally exist, but nothing guarantees it
    can't) is left alone rather than assumed to match;
  - is_staff is False and is_superuser is False -- never delete a
    privileged account this bluntly, regardless of what its other columns
    say.

Race-safe: the criteria above are re-applied, verbatim, in the DELETE
itself (not just `pk__in=[...]` from the earlier SELECT) -- a row that was
activated, given a usable password, logged in, lost its only passkey, or
promoted to staff/superuser in the gap between the two queries must not be
deleted just because it still matches the id a `dry-run` or the listing
step captured earlier.

Intended to run on the same cron schedule as django-oauth-toolkit's own
`cleartokens` -- see docs/remote-mcp-oauth-deploy.md.
"""
import datetime

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone


class Command(BaseCommand):
    help = ('Delete inactive accounts stranded by passkey signup whose '
           'email-verification link has expired (see this command\'s own '
           'module docstring for the exact, conservative criteria).')

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true',
                            help='Print what would be deleted without deleting anything.')

    def _candidates(self, User, cutoff):
        """The exact, conservative criteria from the module docstring --
        entirely DB-level (no Python-side has_usable_password() pass), so
        the same queryset can be re-run unchanged right before the DELETE
        to close the SELECT-then-DELETE race: see the module docstring.

        `.distinct()` because passkeys__isnull=False joins to Passkey, and
        a user with more than one passkey would otherwise appear once per
        row in that join.
        """
        return User.objects.filter(
            is_active=False,
            last_login__isnull=True,
            date_joined__lt=cutoff,
            password__startswith='!',  # Django's UNUSABLE_PASSWORD_PREFIX
            passkeys__isnull=False,
            is_staff=False,
            is_superuser=False,
        ).distinct()

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        User = get_user_model()
        cutoff = timezone.now() - datetime.timedelta(seconds=settings.EMAIL_VERIFICATION_MAX_AGE)

        stranded = list(self._candidates(User, cutoff).order_by('date_joined'))

        if not stranded:
            self.stdout.write('No stranded unactivated accounts found.')
            return

        for user in stranded:
            self.stdout.write(
                '%s user %r (id=%s, email=%r, joined=%s)' % (
                    'Would delete' if dry_run else 'Deleting',
                    user.username, user.pk, user.email, user.date_joined.isoformat()))

        if dry_run:
            self.stdout.write(self.style.WARNING(
                'Dry run: %d account(s) would be deleted.' % len(stranded)))
            return

        with transaction.atomic():
            # Re-apply every criterion, not just pk__in=[...] -- see
            # "Race-safe" in the module docstring. A row that stopped
            # matching since the SELECT above is silently left alone
            # rather than deleted just because its id was captured.
            ids = [user.pk for user in stranded]
            _total, deleted_by_model = self._candidates(User, cutoff).filter(
                pk__in=ids).delete()
        deleted_count = deleted_by_model.get(User._meta.label, 0)
        self.stdout.write(self.style.SUCCESS(
            'Deleted %d stranded account(s).' % deleted_count))
        skipped = len(stranded) - deleted_count
        if skipped:
            self.stdout.write(self.style.WARNING(
                '%d account(s) no longer matched at delete time and were left alone.'
                % skipped))
