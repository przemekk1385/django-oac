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


@pytest.mark.parametrize(
    "request_uri,state_str,expected_exception",
    [
        ("https://example.com/oac/callback/?code=foo", "test", ProviderRequestError),
        (
            "https://example.com/oac/callback/?code=foo&state=bar",
            "baz",
            MismatchingStateError,
        ),
    ],
)
def test__parse_request_uri_method_failure(request_uri, state_str, expected_exception):
    with pytest.raises(expected_exception):
        OAuthClientBackend._parse_request_uri(request_uri, state_str)


def test__parse_request_uri_method_succeeded():
    assert "foo" == OAuthClientBackend._parse_request_uri(
        "https://example.com/oac/callback/?code=foo&state=test", "test"
    )


@pytest.mark.django_db
def test_get_user_does_not_exist():
    assert not OAuthClientBackend.get_user(999)


@pytest.mark.django_db
def test_get_user_succeeded():
    user = UserModel.objects.create(
        first_name="spam", last_name="eggs", email="spam@eggs", username=uuid4().hex
    )

    assert OAuthClientBackend.get_user(user.id)


@patch("django_oac.backends.OAuthClientBackend._parse_request_uri")
def test_authenticate_failure(mock__parse_request_uri, rf):
    mock__parse_request_uri.return_value = "foo"

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


@patch("django_oac.backends.User")
@patch("django_oac.backends.Token")
@patch("django_oac.backends.OAuthClientBackend._parse_request_uri")
def test_authenticate_succeeded(mock__parse_request_uri, mock_token, mock_user, rf):
    user = Mock()
    type(user).email = PropertyMock(return_value="spam@eggs")

    mock__parse_request_uri.return_value = "foo"
    mock_token.remote.get.return_value = Mock(), "foo"
    mock_user.get_from_id_token.return_value = user

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

    assert "spam@eggs" == user.email
