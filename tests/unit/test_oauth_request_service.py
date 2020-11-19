from unittest.mock import Mock, PropertyMock, patch

import pytest

from django_oac.exceptions import ProviderResponseError
from django_oac.services import OAuthRequestService


@patch("django_oac.services.requests")
def test_get_access_token_succeeded(mock_requests):
    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    response.json.return_value = {
        "access_token": "foo",
        "refresh_token": "bar",
        "expires_in": 3600,
        "id_token": "baz",
    }

    mock_requests.post.return_value = response

    service = OAuthRequestService()
    data = service.get_access_token("spam")

    assert data.get("access_token") == "foo"
    assert data.get("refresh_token") == "bar"
    assert data.get("expires_in") == 3600
    assert data.get("id_token") == "baz"


@pytest.mark.parametrize(
    "status_code,expected_message",
    [
        (400, "provider responded with code 400"),
        (200, "provider response is missing required data"),
    ],
)
@patch("django_oac.services.requests")
def test_get_access_token_failed(mock_requests, status_code, expected_message):
    response = Mock()
    type(response).status_code = PropertyMock(return_value=status_code)
    response.json.return_value = {"foo": "bar"}

    mock_requests.post.return_value = response

    service = OAuthRequestService()

    with pytest.raises(ProviderResponseError) as e_info:
        service.get_access_token("spam")

    assert expected_message in str(e_info.value)


@patch("django_oac.services.requests")
def test_refresh_access_token_succeeded(mock_requests):
    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    response.json.return_value = {
        "access_token": "foo",
        "refresh_token": "bar",
        "expires_in": 3600,
        "id_token": "baz",
    }

    mock_requests.post.return_value = response

    service = OAuthRequestService()
    data = service.refresh_access_token("spam")

    assert data.get("access_token") == "foo"
    assert data.get("refresh_token") == "bar"
    assert data.get("expires_in") == 3600
    assert data.get("id_token") == "baz"


@patch("django_oac.services.requests")
def test_refresh_access_token_failed(mock_requests):
    response = Mock()
    type(response).status_code = PropertyMock(return_value=400)
    response.json.return_value = {"foo": "bar"}

    mock_requests.post.return_value = response

    service = OAuthRequestService()

    with pytest.raises(ProviderResponseError):
        service.refresh_access_token("spam")


@patch("django_oac.services.requests")
def test_revoke_refresh_token_failed(mock_requests):
    response = Mock()
    type(response).status_code = PropertyMock(return_value=400)
    response.json.return_value = {"foo": "bar"}

    mock_requests.post.return_value = response

    service = OAuthRequestService()

    with pytest.raises(ProviderResponseError):
        service.revoke_refresh_token("spam")
