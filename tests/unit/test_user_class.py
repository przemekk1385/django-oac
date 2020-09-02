import json
from unittest.mock import Mock, PropertyMock, patch

import pendulum
import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from jwcrypto.common import JWException
from jwt.exceptions import ExpiredSignatureError, PyJWTError

from django_oac.exceptions import InsufficientPayloadError, ProviderResponseError
from django_oac.models import Token, User

from ..common import ID_TOKEN_PAYLOAD, USER_PAYLOAD

UserModel = get_user_model()


def test_get_from_id_token_pyjwt_error():
    with pytest.raises(PyJWTError):
        User.get_from_id_token("foo")


@patch("django_oac.models.requests")
@patch("django_oac.models.jwt")
def test_get_from_id_token_provider_response_error(mock_jwt, mock_requests):
    mock_jwt.get_unverified_header.return_value = {}

    response = Mock()
    type(response).status_code = PropertyMock(return_value=400)

    mock_requests.get.return_value = response

    with pytest.raises(ProviderResponseError) as e_info:
        User.get_from_id_token("foo")

    assert "provider responded with code 400" in str(e_info.value)


@patch("django_oac.models.requests")
def test_get_from_id_token_expired_signature_error(mock_requests, settings, oac_jwt):
    settings.OAC["client_id"] = "foo-bar-baz"
    oac_jwt.kid = "foo"
    oac_jwt.id_token = {
        **ID_TOKEN_PAYLOAD,
        "exp": pendulum.instance(timezone.now()).subtract(years=1),
    }

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=oac_jwt.jwk_set)

    mock_requests.get.return_value = response

    with pytest.raises(ExpiredSignatureError):
        User.get_from_id_token(oac_jwt.id_token)


@pytest.mark.parametrize(
    "jwk,expected_exception", [({"foo": "bar"}, JWException), ({}, PyJWTError)],
)
@patch("django_oac.models.requests")
def test_get_from_id_token_incorrect_jwk(
    mock_requests, jwk, expected_exception, settings, oac_jwt
):
    settings.OAC["client_id"] = "foo-bar-baz"
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=json.dumps({"keys": [jwk]}))

    mock_requests.get.return_value = response

    with pytest.raises(expected_exception):
        User.get_from_id_token(oac_jwt.id_token)


@patch("django_oac.models.requests")
def test_get_from_id_token_missing_jwk(mock_requests, settings, oac_jwt):
    settings.OAC["client_id"] = "foo-bar-baz"
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    id_token = oac_jwt.id_token

    oac_jwt.kid = "bar"

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=oac_jwt.jwk_set)

    mock_requests.get.return_value = response

    with pytest.raises(PyJWTError):
        User.get_from_id_token(id_token)


@pytest.mark.django_db
@patch("django_oac.models.jwt")
@patch("django_oac.models.requests")
def test_get_from_id_token_insufficient_payload(mock_requests, mock_jwt):
    mock_jwt.get_unverified_header.return_value = {}
    mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = None
    mock_jwt.decode.return_value = {}

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=json.dumps({"keys": []}))

    mock_requests.get.return_value = response

    with pytest.raises(InsufficientPayloadError):
        User.get_from_id_token("foo")


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_from_id_token_create_user(mock_requests, oac_jwt, settings):
    settings.OAC["client_id"] = "foo-bar-baz"
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=oac_jwt.jwk_set)

    mock_requests.get.return_value = response

    user = User.get_from_id_token(oac_jwt.id_token)

    assert user.first_name == USER_PAYLOAD["first_name"]
    assert user.last_name == USER_PAYLOAD["last_name"]
    assert user.email == USER_PAYLOAD["email"]
    assert user.username == USER_PAYLOAD["username"]


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_from_id_token_get_existing_user(mock_requests, settings, oac_jwt):
    user = UserModel.objects.create(**USER_PAYLOAD)
    Token.objects.create(
        access_token="foo",
        refresh_token="bar",
        expires_in=3600,
        issued=timezone.now(),
        user=user,
    )

    settings.OAC["client_id"] = "foo-bar-baz"
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=oac_jwt.jwk_set)

    mock_requests.get.return_value = response

    user = User.get_from_id_token(oac_jwt.id_token)

    assert user.first_name == USER_PAYLOAD["first_name"]
    assert user.last_name == USER_PAYLOAD["last_name"]
    assert user.email == USER_PAYLOAD["email"]
    assert user.username == USER_PAYLOAD["username"]
