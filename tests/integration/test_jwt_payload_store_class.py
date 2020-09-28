from unittest.mock import Mock, PropertyMock, patch

from django_oac.stores import JWTPayloadStore

from ..common import ID_TOKEN_PAYLOAD


@patch("django_oac.stores.requests")
@patch("django_oac.stores.cache")
def test_get_succeeded_at_first_attempt(mock_cache, mock_requests, oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=oac_jwt.jwk_set)

    mock_cache.get.return_value = None
    mock_requests.get.return_value = response

    jwt_payload_store = JWTPayloadStore()

    assert not set(ID_TOKEN_PAYLOAD.keys()).difference(
        jwt_payload_store.get(oac_jwt.id_token).keys()
    )


@patch("django_oac.stores.requests")
@patch("django_oac.stores.cache")
def test_get_succeeded_at_second_attempt(mock_cache, mock_requests, oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    valid_key_set = oac_jwt.jwk_set
    id_token = oac_jwt.id_token

    oac_jwt.kid = "foo"

    invalid_key_set = oac_jwt.jwk_set

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=valid_key_set)

    mock_cache.get.return_value = invalid_key_set
    mock_requests.get.return_value = response

    jwt_payload_store = JWTPayloadStore()

    assert not set(ID_TOKEN_PAYLOAD.keys()).difference(
        jwt_payload_store.get(id_token).keys()
    )
