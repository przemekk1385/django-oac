from unittest.mock import patch
from uuid import uuid4

import pytest

from django.utils import timezone

from django_oac.backends import OAuthClientBackend
from django_oac.exceptions import BadRequest, ExpiredState, MismatchingState
from django_oac.models import Token, User

from .helpers import make_mock_request


@pytest.mark.parametrize(
    "request_uri,state_str,exception",
    [
        ("https://example.com/oac/callback/?code=foo", "foo", BadRequest),
        (
            "https://example.com/oac/callback/?code=foo&state=bar",
            "baz",
            MismatchingState,
        ),
    ],
)
def test__parse_request_uri_method_failure(request_uri, state_str, exception):
    with pytest.raises(exception):
        OAuthClientBackend._parse_request_uri(request_uri, state_str)


def test__parse_request_uri_method_succeeded():
    assert (
        OAuthClientBackend._parse_request_uri(
            "https://example.com/oac/callback/?code=foo&state=bar", "bar"
        )
        == "foo"
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

    with pytest.raises(ExpiredState):
        backend.authenticate(mock_request)


@pytest.mark.django_db
@patch("django_oac.backends.User.remote")
@patch("django_oac.backends.Token.remote")
def test_authenticate_succeeded(mock_token, mock_user):
    mock_request = make_mock_request(
        "https://example.com/oac/callback/?code=foo&state=bar",
        {"OAC_STATE_STR": "bar", "OAC_STATE_TIMESTAMP": timezone.now().timestamp(),},
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

    assert user.first_name == "foo"
    assert user.last_name == "bar"
    assert user.email == "foo@bar"
