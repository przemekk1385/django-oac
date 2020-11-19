from unittest.mock import Mock, PropertyMock, patch

import pytest

from django_oac.exceptions import ProviderResponseError
from django_oac.services import OAuthJWKSService


@patch("django_oac.services.requests")
def test_fetch_succeeded(mock_requests, oac_jwk):
    oac_jwk.kid = "foo"

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=oac_jwk.jwks)

    mock_requests.get.return_value = response

    service = OAuthJWKSService()
    jwk, jwks = service.fetch("foo", "bar")

    assert jwk == oac_jwk.jwk
    assert jwks


@patch("django_oac.services.requests")
def test_fetch_failed(mock_requests):
    response = Mock()
    type(response).status_code = PropertyMock(return_value=400)
    type(response).content = PropertyMock(return_value="")

    mock_requests.get.return_value = response

    service = OAuthJWKSService()

    with pytest.raises(ProviderResponseError):
        service.fetch("spam")


def test_clear():
    service = OAuthJWKSService()

    with pytest.raises(NotImplementedError):
        service.clear()


def test_save():
    service = OAuthJWKSService()

    with pytest.raises(NotImplementedError):
        service.save()
