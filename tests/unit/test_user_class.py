import json
from unittest.mock import Mock, PropertyMock, patch
from uuid import uuid4

import pendulum
import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from jwcrypto.common import JWException
from jwt.exceptions import ExpiredSignatureError, PyJWTError

from django_oac.exceptions import InsufficientPayloadError, ProviderResponseError
from django_oac.models import Token, User

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
def test_get_from_id_token_expired_signature_error(mock_requests, settings, oac_jwk):
    settings.OAC["client_id"] = "foo-bar-baz"
    oac_jwk.kid = "foo"
    oac_jwk.id_token = {
        "aud": "foo-bar-baz",
        "exp": pendulum.instance(timezone.now()).subtract(years=1),
        "first_name": "spam",
        "last_name": "eggs",
        "email": "spam@eggs",
    }

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(
        return_value=json.dumps({"keys": [oac_jwk.jwk]})
    )

    mock_requests.get.return_value = response

    with pytest.raises(ExpiredSignatureError):
        User.get_from_id_token(oac_jwk.id_token)


@pytest.mark.parametrize(
    "jwk,expected_exception", [({"foo": "bar"}, JWException), ({}, PyJWTError)],
)
@patch("django_oac.models.requests")
def test_get_from_id_token_incorrect_jwk(
    mock_requests, jwk, expected_exception, settings, oac_jwk
):
    settings.OAC["client_id"] = "foo-bar-baz"
    oac_jwk.kid = "foo"
    oac_jwk.id_token = {
        "aud": "foo-bar-baz",
        "first_name": "spam",
        "last_name": "eggs",
        "email": "spam@eggs",
    }

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(return_value=json.dumps({"keys": [jwk]}))

    mock_requests.get.return_value = response

    with pytest.raises(expected_exception):
        User.get_from_id_token(oac_jwk.id_token)


@patch("django_oac.models.requests")
def test_get_from_id_token_missing_jwk(mock_requests, settings, oac_jwk):
    settings.OAC["client_id"] = "foo-bar-baz"
    oac_jwk.kid = "foo"
    oac_jwk.id_token = {
        "aud": "foo-bar-baz",
        "first_name": "spam",
        "last_name": "eggs",
        "email": "spam@eggs",
    }

    id_token = oac_jwk.id_token

    oac_jwk.kid = "bar"

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(
        return_value=json.dumps({"keys": [oac_jwk.jwk]})
    )

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
def test_get_from_id_token_create_user(mock_requests, oac_jwk, settings):
    settings.OAC["client_id"] = "foo-bar-baz"
    oac_jwk.kid = "foo"
    oac_jwk.id_token = {
        "aud": "foo-bar-baz",
        "first_name": "spam",
        "last_name": "eggs",
        "email": "spam@eggs",
    }

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(
        return_value=json.dumps({"keys": [oac_jwk.jwk]})
    )

    mock_requests.get.return_value = response

    user = User.get_from_id_token(oac_jwk.id_token)

    assert "spam" == user.first_name
    assert "eggs" == user.last_name
    assert "spam@eggs" == user.email
    assert user.username


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_from_id_token_get_existing_user(mock_requests, settings, oac_jwk):
    user = UserModel.objects.create(
        first_name="spam", last_name="eggs", email="spam@eggs", username=uuid4().hex
    )
    Token.objects.create(
        access_token="foo",
        refresh_token="bar",
        expires_in=3600,
        issued=timezone.now(),
        user=user,
    )

    settings.OAC["client_id"] = "foo-bar-baz"
    oac_jwk.kid = "foo"
    oac_jwk.id_token = {
        "aud": "foo-bar-baz",
        "first_name": "spam",
        "last_name": "eggs",
        "email": "spam@eggs",
    }

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    type(response).content = PropertyMock(
        return_value=json.dumps({"keys": [oac_jwk.jwk]})
    )

    mock_requests.get.return_value = response

    user = User.get_from_id_token(oac_jwk.id_token)

    assert "spam" == user.first_name
    assert "eggs" == user.last_name
    assert "spam@eggs" == user.email
    assert user.username
