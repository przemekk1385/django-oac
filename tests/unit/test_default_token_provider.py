from unittest.mock import Mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from django_oac.exceptions import NoUserError
from django_oac.models import Token
from django_oac.models_providers.token_provider import DefaultTokenProvider

from ..common import TOKEN_PAYLOAD, USER_PAYLOAD

UserModel = get_user_model()


@pytest.mark.django_db
def test_create_new_user():
    oauth_request_service = Mock()
    oauth_request_service.get_access_token.return_value = {
        **TOKEN_PAYLOAD,
        "id_token": "baz",
    }

    user = UserModel.objects.create(**USER_PAYLOAD)

    user_provider = Mock()
    user_provider.get_or_create.return_value = user, True

    provider = DefaultTokenProvider(oauth_request_service=oauth_request_service)

    token = provider.create("foo", user_provider=user_provider)

    assert token.access_token == TOKEN_PAYLOAD["access_token"]
    assert token.refresh_token == TOKEN_PAYLOAD["refresh_token"]
    assert token.user.email == USER_PAYLOAD["email"]
    assert token.user.username == USER_PAYLOAD["username"]


@pytest.mark.django_db
def test_create_existing_user():
    oauth_request_service = Mock()
    oauth_request_service.get_access_token.return_value = {
        **TOKEN_PAYLOAD,
        "id_token": "baz",
    }

    user = UserModel.objects.create(**USER_PAYLOAD)
    Token.objects.create(
        issued=timezone.now(),
        user=user,
        **{k: v[::-1] if isinstance(v, str) else v for k, v in TOKEN_PAYLOAD.items()},
    )

    user_provider = Mock()
    user_provider.get_or_create.return_value = user, False

    provider = DefaultTokenProvider(oauth_request_service=oauth_request_service)

    token = provider.create("foo", user_provider=user_provider)

    assert token.access_token == TOKEN_PAYLOAD["access_token"]
    assert token.refresh_token == TOKEN_PAYLOAD["refresh_token"]
    assert token.user.email == USER_PAYLOAD["email"]
    assert token.user.username == USER_PAYLOAD["username"]


@pytest.mark.django_db
def test_create_no_user():
    oauth_request_service = Mock()
    oauth_request_service.get_access_token.return_value = {
        **TOKEN_PAYLOAD,
        "id_token": "baz",
    }

    user_provider = Mock()
    user_provider.get_or_create.return_value = None, False

    provider = DefaultTokenProvider(oauth_request_service=oauth_request_service)

    with pytest.raises(NoUserError):
        provider.create("foo", user_provider=user_provider)


@pytest.mark.django_db
def test_refresh():
    oauth_request_service = Mock()
    oauth_request_service.refresh_access_token.return_value = {
        "access_token": TOKEN_PAYLOAD["access_token"][::-1],
        "refresh_token": TOKEN_PAYLOAD["refresh_token"][::-1],
        "expires_in": 3600,
    }

    token = Token.objects.create(issued=timezone.now(), **TOKEN_PAYLOAD,)

    provider = DefaultTokenProvider(oauth_request_service=oauth_request_service)

    provider.refresh(token)

    assert token.access_token == TOKEN_PAYLOAD["access_token"][::-1]
    assert token.refresh_token == TOKEN_PAYLOAD["refresh_token"][::-1]


@pytest.mark.django_db
def test_revoke():
    oauth_request_service = Mock()

    token = Token.objects.create(issued=timezone.now(), **TOKEN_PAYLOAD,)

    provider = DefaultTokenProvider(oauth_request_service=oauth_request_service())

    provider.revoke(token)

    assert not Token.objects.all()
