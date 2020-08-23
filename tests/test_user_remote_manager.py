import json
from unittest.mock import patch

import jwt
import pendulum
import pytest
from django.utils import timezone
from jwcrypto.jwk import JWK
from jwt.exceptions import ExpiredSignatureError

from django_oac.exceptions import ProviderResponseError
from django_oac.models import User

from .helpers import make_mock_response


@pytest.mark.django_db
@patch("django_oac.models.requests")
@patch("django_oac.models.jwt")
def test_get_failed_request(mock_jwt, mock_request):
    mock_jwt.get_unverified_header.return_value = {"kid": "foo"}
    mock_request.get.return_value = make_mock_response(400, {})

    with pytest.raises(ProviderResponseError) as e_info:
        User.remote.get_from_id_token("foo")

    assert "provider responded with code 400" in str(e_info.value)


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

    assert "spam" == user.first_name
    assert "eggs" == user.last_name
    assert "spam@eggs" == user.email
    assert user.username
