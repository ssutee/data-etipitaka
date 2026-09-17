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
  - has_usable_password() is False -- excludes every *password* signup
    (rest_register) even though it can go stranded the same way: a
    password account might still be retried by other means, and deleting
    one is riskier, so this command's scope is strictly the passkey-only
    case that truly has no recovery path at all;
  - date_joined is at least EMAIL_VERIFICATION_MAX_AGE old -- the same TTL
    auth_views._activate_from_token already enforces on the signed token,
    so this only ever deletes a row whose verification link has
    unconditionally expired already; a fresh signup is left alone even if
    every other condition already matches.

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

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        User = get_user_model()
        cutoff = timezone.now() - datetime.timedelta(seconds=settings.EMAIL_VERIFICATION_MAX_AGE)

        # Narrow with a DB-level filter first (is_active/last_login/
        # date_joined are all plain columns); has_usable_password() is a
        # Python-level check (it does not map to a simple column
        # comparison DjangoORM can push down), so it's applied after, over
        # what should already be a small set.
        candidates = User.objects.filter(
            is_active=False,
            last_login__isnull=True,
            date_joined__lt=cutoff,
        ).order_by('date_joined')

        stranded = [user for user in candidates if not user.has_usable_password()]

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
            User.objects.filter(pk__in=[user.pk for user in stranded]).delete()
        self.stdout.write(self.style.SUCCESS(
            'Deleted %d stranded account(s).' % len(stranded)))
