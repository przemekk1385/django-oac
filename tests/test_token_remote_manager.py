from unittest.mock import patch

import pytest

from django_oac.exceptions import RequestFailed
from django_oac.models import Token

from .helpers import make_mock_response


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_failure(mock_request):
    mock_request.post.return_value = make_mock_response(400, {})
    with pytest.raises(RequestFailed) as e_info:
        Token.remote.get("foo")
    assert e_info.value.status_code == 400


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_succeeded(mock_request):
    mock_request.post.return_value = make_mock_response(
        200,
        {
            "access_token": "foo",
            "refresh_token": "bar",
            "expires_in": 3600,
            "id_token": "baz",
        },
    )
    token = Token.remote.get("spam")
    assert token.access_token == "foo"
    assert token.refresh_token == "bar"
    assert token.expires_in == 3600
    assert not token.has_expired
