import json
from unittest.mock import patch

import jwt
import pendulum
import pytest
from django.utils import timezone
from jwcrypto.jwk import JWK
from jwt.exceptions import ExpiredSignatureError, PyJWTError

from django_oac.exceptions import MissingKtyError, ProviderResponseError
from django_oac.models import User

from .helpers import make_mock_response


def test_get_from_id_token_pyjwt_error():
    with pytest.raises(PyJWTError):
        User.remote.get_from_id_token("foo")


@patch("django_oac.models.requests")
@patch("django_oac.models.jwt")
def test_get_from_id_token_provider_response_error(mock_jwt, mock_requests):
    mock_jwt.get_unverified_header.return_value = {}
    mock_requests.get.return_value = make_mock_response(400, {})

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
    mock_requests.get.return_value = make_mock_response(
        200, {"keys": [json.loads(jwk.export_public())]},
    )

    with pytest.raises(ExpiredSignatureError):
        User.remote.get_from_id_token(id_token)


@patch("django_oac.models.requests")
@pytest.mark.parametrize(
    "jwks,exception",
    [
        ([{"kty": "RSA", "kid": "foo"}], PyJWTError),
        ([{"kid": "foo"}], MissingKtyError),
    ],
)
def test_get_from_id_token_incorrect_jwk(mock_requests, jwks, exception):
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
    mock_requests.get.return_value = make_mock_response(200, {"keys": jwks},)

    with pytest.raises(exception):
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
    mock_requests.get.return_value = make_mock_response(
        200, {"keys": [json.loads(jwk_for_decode.export_public())]},
    )

    with pytest.raises(PyJWTError):
        User.remote.get_from_id_token(id_token)


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_succeeded(mock_requests):
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
    mock_requests.get.return_value = make_mock_response(
        200, {"keys": [json.loads(jwk.export_public())]},
    )

    user = User.remote.get_from_id_token(id_token)

    assert "spam" == user.first_name
    assert "eggs" == user.last_name
    assert "spam@eggs" == user.email
    assert user.username
