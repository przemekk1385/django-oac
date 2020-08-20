import json
from unittest.mock import patch

from jwcrypto.jwk import JWK
from jwt.exceptions import ExpiredSignatureError
import jwt
import pendulum
import pytest

from django.utils import timezone

from django_oac.exceptions import FailedRequest
from django_oac.models import User

from .helpers import make_mock_response


@pytest.mark.django_db
@patch("django_oac.models.requests")
@patch("django_oac.models.jwt")
def test_get_failed_request(mock_jwt, mock_request):
    mock_jwt.get_unverified_header.return_value = {"kid": "foo"}
    mock_request.get.return_value = make_mock_response(400, {})

    with pytest.raises(FailedRequest) as e_info:
        User.remote.get_from_id_token("foo")

    assert e_info.value.status_code == 400


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_expired_signature_error(mock_request):
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
    mock_request.get.return_value = make_mock_response(
        200, {"keys": [json.loads(jwk.export_public())]},
    )

    with pytest.raises(ExpiredSignatureError):
        User.remote.get_from_id_token(id_token)


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_get_succeeded(mock_request):
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
    mock_request.get.return_value = make_mock_response(
        200, {"keys": [json.loads(jwk.export_public())]},
    )

    user = User.remote.get_from_id_token(id_token)

    assert user.first_name == "spam"
    assert user.last_name == "eggs"
    assert user.email == "spam@eggs"
    assert user.username
