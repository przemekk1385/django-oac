import json
from unittest.mock import Mock, PropertyMock, patch
from uuid import uuid4

import jwt
import pendulum
import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from jwcrypto.jwk import JWK
from jwt.exceptions import ExpiredSignatureError, PyJWTError

from django_oac.exceptions import (
    InsufficientPayloadError,
    MissingKtyError,
    ProviderResponseError,
)
from django_oac.models import Token, User

UserModel = get_user_model()


def test_get_from_id_token_pyjwt_error():
    with pytest.raises(PyJWTError):
        User.remote.get_from_id_token("foo")


@patch("django_oac.models.requests")
@patch("django_oac.models.jwt")
def test_get_from_id_token_provider_response_error(mock_jwt, mock_requests):
    mock_jwt.get_unverified_header.return_value = {}

    response = Mock()
    type(response).status_code = PropertyMock(return_value=400)

    mock_requests.get.return_value = response

    with pytest.raises(ProviderResponseError) as e_info:
        User.remote.get_from_id_token("foo")

    assert "provider responded with code 400" in str(e_info.value)


@patch("django_oac.models.requests")
def test_get_from_id_token_expired_signature_error(mock_requests):
    jwk = JWK.generate(kty="RSA", use="sig", alg="RS256", kid="foo", x5t="foo")
    secret = jwk.export_to_pem(private_key=True, password=None).decode("utf-8")
    id_token = jwt.encode(
        {
            "aud": "foo-bar-baz",
            "exp": pendulum.instance(timezone.now()).subtract(years=1),
            "first_name": "spam",
            "last_name": "eggs",
            "email": "spam@eggs",
        },
        secret,
        algorithm="RS256",
        headers={"alg": "RS256", "kid": "foo", "x5t": "foo"},
    ).decode("utf-8")

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    response.json.return_value = {"keys": [json.loads(jwk.export_public())]}

    mock_requests.get.return_value = response

    with pytest.raises(ExpiredSignatureError):
        User.remote.get_from_id_token(id_token)


@pytest.mark.parametrize(
    "key,expected_exception",
    [({"kty": "RSA", "kid": "foo"}, PyJWTError), ({"kid": "foo"}, MissingKtyError),],
)
@patch("django_oac.models.requests")
def test_get_from_id_token_incorrect_jwk(mock_requests, key, expected_exception):
    jwk = JWK.generate(kty="RSA", use="sig", alg="RS256", kid="foo", x5t="foo")
    secret = jwk.export_to_pem(private_key=True, password=None).decode("utf-8")
    id_token = jwt.encode(
        {
            "aud": "foo-bar-baz",
            "exp": pendulum.instance(timezone.now()).subtract(years=1),
            "first_name": "spam",
            "last_name": "eggs",
            "email": "spam@eggs",
        },
        secret,
        algorithm="RS256",
        headers={"alg": "RS256", "kid": "foo", "x5t": "foo"},
    ).decode("utf-8")

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    response.json.return_value = {"keys": [key]}

    mock_requests.get.return_value = response

    with pytest.raises(expected_exception):
        User.remote.get_from_id_token(id_token)


@patch("django_oac.models.requests")
def test_get_from_id_token_missing_jwk(mock_requests):
    jwk_for_encode = JWK.generate(
        kty="RSA", use="sig", alg="RS256", kid="foo", x5t="foo"
    )
    jwk_for_decode = JWK.generate(
        kty="RSA", use="sig", alg="RS256", kid="bar", x5t="bar"
    )
    secret = jwk_for_encode.export_to_pem(private_key=True, password=None).decode(
        "utf-8"
    )
    id_token = jwt.encode(
        {
            "aud": "foo-bar-baz",
            "exp": pendulum.instance(timezone.now()).subtract(years=1),
            "first_name": "spam",
            "last_name": "eggs",
            "email": "spam@eggs",
        },
        secret,
        algorithm="RS256",
        headers={"alg": "RS256", "kid": "foo", "x5t": "foo"},
    ).decode("utf-8")

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    response.json.return_value = {"keys": [json.loads(jwk_for_decode.export_public())]}

    mock_requests.get.return_value = response

    with pytest.raises(PyJWTError):
        User.remote.get_from_id_token(id_token)


@pytest.mark.django_db
@patch("django_oac.models.jwt")
@patch("django_oac.models.requests")
def test_get_from_id_token_insufficient_payload(mock_requests, mock_jwt):
    mock_jwt.get_unverified_header.return_value = {}
    mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = None
    mock_jwt.decode.return_value = {}

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    response.json.return_value = {"keys": []}

    mock_requests.get.return_value = response

    with pytest.raises(InsufficientPayloadError):
        User.remote.get_from_id_token("foo")


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_from_id_token_create_user(mock_requests):
    jwk = JWK.generate(kty="RSA", use="sig", alg="RS256", kid="foo", x5t="foo")
    secret = jwk.export_to_pem(private_key=True, password=None).decode("utf-8")
    id_token = jwt.encode(
        {
            "aud": "foo-bar-baz",
            "first_name": "spam",
            "last_name": "eggs",
            "email": "spam@eggs",
        },
        secret,
        algorithm="RS256",
        headers={"alg": "RS256", "kid": "foo", "x5t": "foo"},
    ).decode("utf-8")

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    response.json.return_value = {"keys": [json.loads(jwk.export_public())]}

    mock_requests.get.return_value = response

    user = User.remote.get_from_id_token(id_token)

    assert "spam" == user.first_name
    assert "eggs" == user.last_name
    assert "spam@eggs" == user.email
    assert user.username


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_from_id_token_get_existing_user(mock_requests):
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

    jwk = JWK.generate(kty="RSA", use="sig", alg="RS256", kid="foo", x5t="foo")
    secret = jwk.export_to_pem(private_key=True, password=None).decode("utf-8")
    id_token = jwt.encode(
        {
            "aud": "foo-bar-baz",
            "first_name": "spam",
            "last_name": "eggs",
            "email": "spam@eggs",
        },
        secret,
        algorithm="RS256",
        headers={"alg": "RS256", "kid": "foo", "x5t": "foo"},
    ).decode("utf-8")

    response = Mock()
    type(response).status_code = PropertyMock(return_value=200)
    response.json.return_value = {"keys": [json.loads(jwk.export_public())]}

    mock_requests.get.return_value = response

    user = User.remote.get_from_id_token(id_token)

    assert "spam" == user.first_name
    assert "eggs" == user.last_name
    assert "spam@eggs" == user.email
    assert user.username
