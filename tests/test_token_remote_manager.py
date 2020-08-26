from unittest.mock import MagicMock, Mock, patch

import pytest

from django_oac.exceptions import ProviderResponseError
from django_oac.models import Token


@pytest.mark.django_db
@pytest.mark.parametrize(
    "status_code,expected_message",
    [
        (400, "provider responded with code 400"),
        (200, "provider response is missing required data"),
    ],
)
@patch("django_oac.models.requests")
def test_get_failure(mock_requests, status_code, expected_message):
    response = MagicMock()
    type(response).status_code = status_code

    mock_requests.post.return_value = response

    with pytest.raises(ProviderResponseError) as e_info:
        Token.remote.get("foo")

    assert expected_message in str(e_info.value)


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_succeeded(mock_requests):
    response = Mock()
    type(response).status_code = 200
    response.json.return_value = {
        "access_token": "foo",
        "refresh_token": "bar",
        "expires_in": 3600,
        "id_token": "baz",
    }

    mock_requests.post.return_value = response

    token, id_token = Token.remote.get("spam")

    assert "foo" == token.access_token
    assert "bar" == token.refresh_token
    assert 3600 == token.expires_in
    assert not token.has_expired
