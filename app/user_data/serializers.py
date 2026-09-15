from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers


class AccountIdentitySerializer(serializers.Serializer):
    """Username + email rules shared by password signup and passkey signup."""
    email = serializers.EmailField(max_length=254)
    username = serializers.CharField(max_length=150,
                                     validators=[UnicodeUsernameValidator()])

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError(_("A user with that username already exists."))
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
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
