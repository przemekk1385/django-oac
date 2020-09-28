from unittest.mock import Mock

import pendulum
import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from jwt.exceptions import ExpiredSignatureError, PyJWTError

from django_oac.exceptions import InsufficientPayloadError
from django_oac.stores import JWTPayloadStore

from ..common import ID_TOKEN_PAYLOAD

UserModel = get_user_model()


def test_get_expired_signature_error(oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = {
        **ID_TOKEN_PAYLOAD,
        "exp": pendulum.instance(timezone.now()).subtract(years=1),
    }

    jwk_store = Mock()
    jwk_store.get.return_value = oac_jwt.jwk

    jwt_payload_store = JWTPayloadStore(jwk_store=jwk_store)

    with pytest.raises(ExpiredSignatureError):
        jwt_payload_store.get(oac_jwt.id_token)


def test_get_pyjwt_error():
    jwt_payload_store = JWTPayloadStore()

    with pytest.raises(PyJWTError):
        jwt_payload_store.get("foo")


def test_get_insufficient_payload_error(oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    required_fields = list(ID_TOKEN_PAYLOAD.keys())
    required_fields.append("bar")

    jwk_store = Mock()
    jwk_store.get.return_value = oac_jwt.jwk

    jwt_payload_store = JWTPayloadStore(required_fields, jwk_store=jwk_store)

    with pytest.raises(InsufficientPayloadError):
        jwt_payload_store.get(oac_jwt.id_token)


def test_get_succeeded_at_first_attempt(oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    jwk_store = Mock()
    jwk_store.get.return_value = oac_jwt.jwk

    jwt_payload_store = JWTPayloadStore(jwk_store=jwk_store)

    assert not set(ID_TOKEN_PAYLOAD.keys()).difference(
        jwt_payload_store.get(oac_jwt.id_token).keys()
    )


def test_get_succeeded_at_second_attempt(oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    valid_key = oac_jwt.jwk
    id_token = oac_jwt.id_token

    oac_jwt.kid = "foo"

    invalid_key = oac_jwt.jwk

    jwk_store = Mock()
    jwk_store.get.side_effect = [invalid_key, valid_key]

    jwt_payload_store = JWTPayloadStore(jwk_store=jwk_store)

    assert not set(ID_TOKEN_PAYLOAD.keys()).difference(
        jwt_payload_store.get(id_token).keys()
    )
