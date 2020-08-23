from unittest.mock import patch
from uuid import uuid4

import pytest
from django.utils import timezone

from django_oac.backends import OAuthClientBackend
from django_oac.exceptions import (
    ExpiredStateError,
    MismatchingStateError,
    ProviderRequestError,
)
from django_oac.models import Token, User

from .helpers import make_mock_request


@pytest.mark.parametrize(
    "request_uri,state_str,expected_exception",
    [
        ("https://example.com/oac/callback/?code=foo", "foo", ProviderRequestError),
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
        "https://example.com/oac/callback/?code=foo&state=bar", "bar"
    )


def test_authenticate_failure():
    mock_request = make_mock_request(
        "https://example.com/oac/callback/?code=foo&state=bar",
        {
            "OAC_STATE_STR": "bar",
            "OAC_STATE_TIMESTAMP": timezone.now().timestamp() - 301,
        },
    )
    backend = OAuthClientBackend()

    with pytest.raises(ExpiredStateError):
        backend.authenticate(mock_request)


@pytest.mark.django_db
@patch("django_oac.backends.User.remote")
@patch("django_oac.backends.Token.remote")
def test_authenticate_succeeded(mock_token, mock_user):
    mock_request = make_mock_request(
        "https://example.com/oac/callback/?code=foo&state=bar",
        {"OAC_STATE_STR": "bar", "OAC_STATE_TIMESTAMP": timezone.now().timestamp()},
    )
    mock_token.get.return_value = (
        Token(
            access_token="foo",
            refresh_token="bar",
            expires_in=3600,
            issued=timezone.now(),
        ),
        "foo",
    )
    mock_user.get_from_id_token.return_value = User.objects.create(
        first_name="foo", last_name="bar", email="foo@bar", username=uuid4().hex
    )
    backend = OAuthClientBackend()

    user = backend.authenticate(mock_request)

    assert "foo" == user.first_name
    assert "bar" == user.last_name
    assert "foo@bar" == user.email
    assert user.username
