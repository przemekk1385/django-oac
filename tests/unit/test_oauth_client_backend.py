from unittest.mock import Mock, PropertyMock, patch
from uuid import uuid4

import pytest
from django.contrib.auth import get_user_model

from django_oac.backends import OAuthClientBackend

UserModel = get_user_model()


@pytest.mark.django_db
def test_get_user_does_not_exist():
    assert not OAuthClientBackend.get_user(999)


@pytest.mark.django_db
def test_get_user_succeeded():
    user = UserModel.objects.create(
        first_name="spam", last_name="eggs", email="spam@eggs", username=uuid4().hex
    )

    assert OAuthClientBackend.get_user(user.id)


@patch("django_oac.backends.JWTPayloadStore")
@patch("django_oac.backends.Token")
@patch("django_oac.backends.UserModel")
def test_authenticate_succeeded(
    mock_user_model, mock_token, mock_jwt_payload_store, oac_valid_get_request
):
    user = Mock()
    type(user).email = PropertyMock(return_value="spam@eggs")

    jwt_payload_store = Mock()
    jwt_payload_store.return_value = {}

    mock_token.remote.get.return_value = Mock(), "bar"
    mock_jwt_payload_store.get.return_value = jwt_payload_store
    mock_user_model.objects.get.return_value = user

    backend = OAuthClientBackend()

    user = backend.authenticate(oac_valid_get_request)

    assert user.email == "spam@eggs"
