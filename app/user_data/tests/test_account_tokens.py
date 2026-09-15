"""Tests for user_data.account_tokens.revoke_all_tokens."""
from datetime import timedelta

import pytest
from django.utils import timezone
from oauth2_provider.models import AccessToken, Grant, IDToken, RefreshToken
from rest_framework.authtoken.models import Token

from user_data.account_tokens import revoke_all_tokens

from .conftest import make_oauth_token

pytestmark = pytest.mark.django_db


def _grant(user, application, code):
    return Grant.objects.create(
        user=user, application=application, code=code,
        expires=timezone.now() + timedelta(minutes=5),
        redirect_uri='https://app.example/cb', scope='etipitaka:read')


def _id_token(user, application):
    return IDToken.objects.create(
        user=user, application=application,
        expires=timezone.now() + timedelta(minutes=5), scope='etipitaka:read')


def test_revoke_all_tokens_removes_drf_and_oauth_tokens(alice, bob):
    access = make_oauth_token(alice)
    RefreshToken.objects.create(user=alice, application=access.application,
                                token='r-1', access_token=access)
    _grant(alice, access.application, 'c-alice')
    _id_token(alice, access.application)

    bob_access = make_oauth_token(bob)
    RefreshToken.objects.create(user=bob, application=bob_access.application,
                                token='r-bob', access_token=bob_access)
    _grant(bob, bob_access.application, 'c-bob')
    _id_token(bob, bob_access.application)

    revoke_all_tokens(alice)

    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert not RefreshToken.objects.filter(user=alice).exists()
    assert not Grant.objects.filter(user=alice).exists()
    assert not IDToken.objects.filter(user=alice).exists()

    assert Token.objects.filter(user=bob).exists()
    assert AccessToken.objects.filter(user=bob).exists()
    assert RefreshToken.objects.filter(user=bob).exists()
    assert Grant.objects.filter(user=bob).exists()
    assert IDToken.objects.filter(user=bob).exists()


def test_revoke_all_tokens_blocks_further_api_access(api, alice):
    """A live bearer token stops authenticating once revoked -- not just
    deleted from the table, but actually rejected by the API."""
    tok = make_oauth_token(alice)
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    assert api.get('/rest-auth/user/').status_code == 200

    revoke_all_tokens(alice)

    resp = api.get('/rest-auth/user/')
    assert resp.status_code == 401
