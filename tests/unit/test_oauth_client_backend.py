from unittest.mock import Mock, PropertyMock

import pytest
from django.contrib.auth import get_user_model

from django_oac.backends import OAuthClientBackend
from django_oac.exceptions import NoUserError

from ..common import USER_PAYLOAD

UserModel = get_user_model()


@pytest.mark.django_db
def test_get_user_does_not_exist():
    assert not OAuthClientBackend.get_user(999)


@pytest.mark.django_db
def test_get_user_succeeded():
    user = UserModel.objects.create(**USER_PAYLOAD)

    assert OAuthClientBackend.get_user(user.id)


@pytest.mark.django_db
def test_authenticate_succeeded(oac_valid_get_request):
    user = UserModel.objects.create(**USER_PAYLOAD)

    token = Mock()
    type(token).user = PropertyMock(return_value=user)

    token_provider = Mock()
    token_provider.create.return_value = token

    authenticated_user = OAuthClientBackend.authenticate(
        oac_valid_get_request, token_provider=token_provider
    )

    assert authenticated_user.email == USER_PAYLOAD["email"]


def test_authenticate_no_user_error(oac_valid_get_request):
    token_provider = Mock()
    token_provider.create.side_effect = NoUserError("foo")

    assert not OAuthClientBackend.authenticate(
        oac_valid_get_request, token_provider=token_provider
    )
