from unittest.mock import Mock, PropertyMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache

from django_oac.models import JWKS

UserModel = get_user_model()


def _get_from_uri():
    cache.set("foo", "bar")


@patch("django_oac.models.cache")
@patch("django_oac.models.sha1")
def test__get_from_cache(mock_sha1, mock_cache, oac_jwk):
    mock_sha1().hexdigest.return_value = "foo"
    mock_cache.get.return_value = oac_jwk.jwk_set

    jwks = JWKS("bar")

    assert jwks._get_from_cache() == oac_jwk.jwk_set


@patch("django_oac.models.requests")
@patch("django_oac.models.sha1")
def test__get_from_uri(mock_sha1, mock_requests, oac_jwk):
    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=oac_jwk.jwk_set)

    mock_sha1().hexdigest.return_value = "foo"
    mock_requests.get.return_value = response

    jwks = JWKS("bar")

    assert jwks._get_from_uri() == oac_jwk.jwk_set


@patch("django_oac.models.JWKS._get_from_cache")
@patch("django_oac.models.sha1")
def test_get_cached_key(mock_sha1, mock__get_from_cache, oac_jwk):
    oac_jwk.kid = "foo"

    mock_sha1().hexdigest.return_value = "bar"
    mock__get_from_cache.return_value = oac_jwk.jwk_set

    jwks = JWKS("baz")

    assert jwks.get("foo") == oac_jwk.jwk


@patch("django_oac.models.JWKS._get_from_uri")
@patch("django_oac.models.JWKS._get_from_cache")
@patch("django_oac.models.sha1")
def test_get_non_cached_key(
    mock_sha1, mock__get_from_cache, mock__get_from_uri, oac_jwk
):
    oac_jwk.kid = "foo"

    mock_sha1().hexdigest.return_value = "bar"
    mock__get_from_cache.return_value = None
    mock__get_from_uri.return_value = oac_jwk.jwk_set

    jwks = JWKS("baz")

    assert jwks.get("foo") == oac_jwk.jwk


@patch("django_oac.models.JWKS._get_from_uri")
def test_refresh(mock__get_from_uri):

    mock__get_from_uri.return_value = "foo"
    mock__get_from_uri.side_effect = _get_from_uri

    jwks = JWKS("bar")
    jwks.refresh()

    assert cache.get("foo") == "bar"
