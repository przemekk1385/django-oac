from unittest.mock import Mock, patch

import pendulum
import pytest
from django.utils import timezone

from django_oac.exceptions import ProviderResponseError
from django_oac.models import Token


@pytest.mark.django_db
def test_has_expired_property():
    payload = {
        "access_token": "foo",
        "refresh_token": "bar",
        "expires_in": 3600,
        "issued": pendulum.instance(timezone.now()).subtract(seconds=3601),
    }

    token = Token.objects.create(**payload)

    assert token.has_expired


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_refresh_method_failure(mock_requests):
    response = Mock()
    type(response).status_code = 400

    token = Token.objects.create(
        access_token="foo",
        refresh_token="bar",
        expires_in=3600,
        issued=pendulum.instance(timezone.now()).subtract(seconds=3601),
    )

    mock_requests.post.return_value = response

    with pytest.raises(ProviderResponseError) as e_info:
        token.refresh()

    assert "provider responded with code 400" in str(e_info.value)


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_refresh_method_succeeded(mock_requests):
    response = Mock()
    type(response).status_code = 200
    response.json.return_value = {
        "access_token": "spam",
        "refresh_token": "eggs",
        "expires_in": 3600,
    }

    token = Token.objects.create(
        access_token="foo",
        refresh_token="bar",
        expires_in=3600,
        issued=pendulum.instance(timezone.now()).subtract(seconds=3601),
    )

    mock_requests.post.return_value = response

    token.refresh()

    assert "spam" == token.access_token
    assert "eggs" == token.refresh_token
    assert 3600 == token.expires_in
    assert not token.has_expired


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_revoke_method_failure(mock_requests):
    response = Mock()
    type(response).status_code = 400

    token = Token.objects.create(
        access_token="foo",
        refresh_token="bar",
        expires_in=3600,
        issued=pendulum.instance(timezone.now()).subtract(seconds=3601),
    )

    mock_requests.post.return_value = response

    with pytest.raises(ProviderResponseError) as e_info:
        token.revoke()

    assert "provider responded with code 400" in str(e_info.value)
