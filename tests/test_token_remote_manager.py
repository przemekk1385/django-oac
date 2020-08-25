from unittest.mock import patch

import pytest

from django_oac.exceptions import ProviderResponseError
from django_oac.models import Token

from .helpers import make_mock_response


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_failure(mock_requests):
    mock_requests.post.return_value = make_mock_response(400, {})

    with pytest.raises(ProviderResponseError) as e_info:
        Token.remote.get("foo")

    assert "provider responded with code 400" in str(e_info.value)


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_succeeded(mock_requests):
    mock_requests.post.return_value = make_mock_response(
        200,
        {
            "access_token": "foo",
            "refresh_token": "bar",
            "expires_in": 3600,
            "id_token": "baz",
        },
    )

    token, id_token = Token.remote.get("spam")

    assert "foo" == token.access_token
    assert "bar" == token.refresh_token
    assert 3600 == token.expires_in
    assert not token.has_expired
