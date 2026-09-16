from django.contrib.auth import authenticate
from django.contrib.auth.forms import _unicode_ci_compare
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from .account_tokens import lock_signup_email


def _username_taken(username):
    """True iff some user's username matches `username` case-insensitively.

    `username` must already be normalised (User.normalize_username, NFKC) --
    see validate_username below, the only caller -- so a simple __iexact
    against the stored (also-normalised, per validate_username's own
    docstring) usernames is enough: both sides went through the same NFKC
    pass, so there is no compatibility-equivalent spelling left for a plain
    case-fold to miss the way there could be for email (see _email_taken).
    """
    return User.objects.filter(username__iexact=username).exists()


def _email_taken(email):
    """True iff some user's email is `email` under the same case-insensitive
    equivalence AccountRecoveryForm.get_users (recovery.py) already uses:
    an __iexact filter to cheaply narrow candidates without scanning every
    row, then django.contrib.auth.forms._unicode_ci_compare (NFKC-normalise
    both sides, then casefold) to decide for real. Using the exact same
    helper recovery relies on -- rather than a hand-rolled equivalent -- is
    what keeps "is this email taken" (here) and "which account does this
    email belong to" (recovery) from ever disagreeing about some Unicode
    edge case one of the two checks alone would get wrong.
    """
    return any(_unicode_ci_compare(email, existing)
              for existing in User.objects.filter(email__iexact=email)
                                          .values_list('email', flat=True))


class AccountIdentitySerializer(serializers.Serializer):
    """Username + email rules shared by password signup and passkey signup."""
    email = serializers.EmailField(max_length=254)
    username = serializers.CharField(max_length=150,
                                     validators=[UnicodeUsernameValidator()])

    def validate_username(self, value):
        """Reject a username that collides case-insensitively with an
        existing one, and normalise it (NFKC, via User.normalize_username --
        the same normalisation AbstractUser.clean() applies, which
        create_user's own full_clean()-free path never runs) so the
        normalised spelling, not the caller's raw one, is what ends up in
        validated_data and ultimately gets stored: without this, a fullwidth
        `ｎｅｗｂｉｅ` would be accepted as a different account from
        `newbie` even though they render identically and NFKC treats them
        as the same string.
        """
        normalized = User.normalize_username(value)
        if _username_taken(normalized):
            raise serializers.ValidationError(_("A user with that username already exists."))
        return normalized

    def validate_email(self, value):
        """Reject an email that collides case-insensitively with an existing
        one. `value` can never actually be '' here -- EmailField defaults to
        required=True, allow_blank=False, so a blank/missing email is
        already rejected by field-level validation before this method ever
        runs -- but the guard is kept anyway as a defensive backstop against
        that field configuration ever changing, so two blank emails could
        never look like a collision to _email_taken (which would otherwise
        report every blank-email row as matching every other one).
        """
        if not value:
            return value
        if _email_taken(value):
            raise serializers.ValidationError(_("A user with that email already exists."))
        return value


class RegisterSerializer(AccountIdentitySerializer):
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['password1'] != attrs['password2']:
            raise serializers.ValidationError({"password": _("The two password fields didn't match.")})
        # Enforce AUTH_PASSWORD_VALIDATORS, as the old allauth signup did.
        try:
            validate_password(attrs['password1'])
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"password": list(exc.messages)})
        return attrs

    def create(self, validated_data):
        """Create the inactive account -- under the same per-email advisory
        lock, and the same re-check-right-before-insert pattern,
        passkey_service.finish_signup uses to close its own same-email
        race: validate() above already ran is_valid()'s validate_email
        (and so already found the email free) *before* this method was
        ever called, with no lock held over that gap, so a second request
        for the same email can slip its own is_valid() in before this one
        commits. Without re-checking here, under lock_signup_email, both
        requests would sail through to their own user.save() and the
        database -- which enforces uniqueness on username, not email --
        would let both succeed.

        Raising serializers.ValidationError from inside create() (called
        via serializer.save(), not is_valid()) still turns into the same
        400 + {"email": [...]} shape a caller would see from a same-request
        validation failure: rest_register runs inside an @api_view view,
        and DRF's default exception handler turns any APIException
        (ValidationError is one) raised anywhere in that call stack into
        Response(exc.detail, status=exc.status_code) -- exc.detail here
        already being the same {"email": [...]} dict shape as
        AccountIdentitySerializer.validate_email's own error, since dict
        detail is passed through as-is rather than wrapped.

        Username needs no equivalent re-check: the database's own unique
        index on username (case-sensitive, unlike this email check) still
        catches an exact-duplicate race as an IntegrityError -- ugly (a raw
        500 today, both before and after this change), but not a silent
        double-account the way the email race was.
        """
        with transaction.atomic():
            lock_signup_email(validated_data['email'])
            if _email_taken(validated_data['email']):
                raise serializers.ValidationError(
                    {'email': [_("A user with that email already exists.")]})
            user = User(username=validated_data['username'],
                        email=validated_data['email'],
                        is_active=False)
            user.set_password(validated_data['password1'])
            user.save()
            return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = authenticate(username=attrs['username'], password=attrs['password'])
        if user is None:
            raise serializers.ValidationError(
                {"non_field_errors": [_("Unable to log in with provided credentials.")]})
        if not user.is_active:
            raise serializers.ValidationError(
                {"non_field_errors": [_("This account is not active. Please verify your email.")]})
        attrs['user'] = user
        return attrs
