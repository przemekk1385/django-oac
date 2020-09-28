from unittest.mock import Mock, PropertyMock, patch
from uuid import uuid4

import pytest
from django.contrib.auth import get_user_model
from django.shortcuts import reverse
from django.utils import timezone

from django_oac.backends import OAuthClientBackend
from django_oac.exceptions import (
    ExpiredStateError,
    MismatchingStateError,
    ProviderRequestError,
)

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


# pylint: disable=invalid-name, protected-access
def test_authenticate_provider_request_error(rf):
    request = rf.get(reverse("django_oac:authenticate"), {"state": "test"})
    request.session = {
        "OAC_STATE_STR": "test",
        "OAC_STATE_TIMESTAMP": timezone.now().timestamp(),
        "OAC_CLIENT_IP": "127.0.0.1",
    }

    backend = OAuthClientBackend()

    with pytest.raises(ProviderRequestError):
        backend.authenticate(request)


# pylint: disable=invalid-name, protected-access
def test_authenticate_mismatching_state_error(rf):
    request = rf.get(
        reverse("django_oac:authenticate"), {"code": "foo", "state": "bar"}
    )
    request.session = {
        "OAC_STATE_STR": "test",
        "OAC_STATE_TIMESTAMP": timezone.now().timestamp(),
        "OAC_CLIENT_IP": "127.0.0.1",
    }

    backend = OAuthClientBackend()

    with pytest.raises(MismatchingStateError):
        backend.authenticate(request)


# pylint: disable=invalid-name, protected-access
def test_authenticate_expired_state_error(rf):
    request = rf.get(
        reverse("django_oac:authenticate"), {"code": "foo", "state": "test"}
    )
    request.session = {
        "OAC_STATE_STR": "test",
        "OAC_STATE_TIMESTAMP": timezone.now().timestamp() - 301,
        "OAC_CLIENT_IP": "127.0.0.1",
    }
    backend = OAuthClientBackend()

    with pytest.raises(ExpiredStateError):
        backend.authenticate(request)


# pylint: disable=invalid-name, protected-access
@patch("django_oac.backends.JWTPayloadStore")
@patch("django_oac.backends.Token")
@patch("django_oac.backends.UserModel")
def test_authenticate_succeeded(
    mock_user_model, mock_token, mock_jwt_payload_store, rf
):
    user = Mock()
    type(user).email = PropertyMock(return_value="spam@eggs")

    jwt_payload_store = Mock()
    jwt_payload_store.return_value = {}

    mock_token.remote.get.return_value = Mock(), "bar"
    mock_jwt_payload_store.get.return_value = jwt_payload_store
    mock_user_model.objects.get.return_value = user

    request = rf.get(
        reverse("django_oac:authenticate"), {"code": "foo", "state": "test"}
    )
    request.session = {
        "OAC_STATE_STR": "test",
        "OAC_STATE_TIMESTAMP": timezone.now().timestamp(),
        "OAC_CLIENT_IP": "127.0.0.1",
    }
    backend = OAuthClientBackend()

    user = backend.authenticate(request)

    assert user.email == "spam@eggs"
