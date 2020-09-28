import json
from unittest.mock import Mock, patch, PropertyMock

import pytest
from django.contrib.auth import get_user_model
from jwcrypto.jwk import JWException

from django_oac.exceptions import KeyNotFoundError, ProviderResponseError
from django_oac.stores import JWKStore

UserModel = get_user_model()


@patch("django_oac.stores.JWKStore._get_cached")
@patch("django_oac.stores.sha1")
def test_get_cached_key(mock_sha1, mock__get_cached, oac_jwk):
    oac_jwk.kid = "foo"

    mock_sha1().hexdigest.return_value = "bar"
    mock__get_cached.return_value = oac_jwk.jwk_set

    jwk_set_store = JWKStore()

    assert oac_jwk.jwk == jwk_set_store.get("foo")


@patch("django_oac.stores.JWKStore._get_from_uri")
@patch("django_oac.stores.JWKStore._get_cached")
@patch("django_oac.stores.sha1")
def test_get_key_from_uri(mock_sha1, mock__get_cached, mock__get_from_uri, oac_jwk):
    oac_jwk.kid = "foo"

    mock_sha1().hexdigest.return_value = "bar"
    mock__get_cached.return_value = None
    mock__get_from_uri.return_value = oac_jwk.jwk_set

    jwk_set_store = JWKStore()

    assert oac_jwk.jwk == jwk_set_store.get("foo")


@patch("django_oac.stores.JWKStore._get_from_uri")
@patch("django_oac.stores.JWKStore._get_cached")
@patch("django_oac.stores.sha1")
def test_get_key_not_found_error(
    mock_sha1, mock__get_cached, mock__get_from_uri, oac_jwk
):
    oac_jwk.kid = "foo"

    mock_sha1().hexdigest.return_value = "bar"
    mock__get_cached.return_value = None
    mock__get_from_uri.return_value = oac_jwk.jwk_set

    jwk_set_store = JWKStore()

    with pytest.raises(KeyNotFoundError):
        jwk_set_store.get("baz")


@patch("django_oac.stores.requests")
@patch("django_oac.stores.JWKStore._get_cached")
@patch("django_oac.stores.sha1")
def test_get_provider_response_error(
    mock_sha1, mock__get_cached, mock_requests, oac_jwk
):
    oac_jwk.kid = "foo"

    response = Mock()
    type(response).status_code = PropertyMock(return_value=400)

    mock_sha1().hexdigest.return_value = "bar"
    mock__get_cached.return_value = None
    mock_requests.get.return_value = response

    jwk_set_store = JWKStore()

    with pytest.raises(ProviderResponseError):
        jwk_set_store.get("foo")


@patch("django_oac.stores.JWKStore._get_cached")
@patch("django_oac.stores.sha1")
def test_get_jw_exception(
    mock_sha1, mock__get_cached,
):
    mock_sha1().hexdigest.return_value = "bar"
    mock__get_cached.return_value = json.dumps({"keys": [{"kty": "foo"}],})

    jwk_set_store = JWKStore()

    with pytest.raises(JWException):
        jwk_set_store.get("foo")
