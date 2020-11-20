from copy import copy
from unittest.mock import Mock

import pytest
from django.contrib.auth import get_user_model
from jwt.exceptions import InvalidSignatureError

from django_oac.exceptions import InsufficientPayloadError
from django_oac.models_providers.user_provider import DefaultUserProvider

from ..common import ID_TOKEN_PAYLOAD, USER_PAYLOAD

UserModel = get_user_model()


@pytest.mark.django_db
def test_get_or_create_new_user_cached_jwks(oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    mock_jwks_service = Mock()
    mock_jwks_service.fetch.return_value = oac_jwt.jwk, oac_jwt.jwks

    provider = DefaultUserProvider()

    user, created = provider.get_or_create(
        oac_jwt.id_token,
        lookup_field="email",
        fetch_from_services=[mock_jwks_service, mock_jwks_service],
        save_by_service=mock_jwks_service,
    )

    assert created
    assert user.email == ID_TOKEN_PAYLOAD["email"]
    assert user.username == ID_TOKEN_PAYLOAD["username"]


@pytest.mark.django_db
def test_get_or_create_new_user_remote_jwks(oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    mock_jwks_service = Mock()
    mock_jwks_service.fetch.side_effect = [(None, None), (oac_jwt.jwk, oac_jwt.jwks)]
    mock_jwks_service.save.return_value = None

    provider = DefaultUserProvider()

    user, created = provider.get_or_create(
        oac_jwt.id_token,
        lookup_field="email",
        fetch_from_services=[mock_jwks_service, mock_jwks_service],
        save_by_service=mock_jwks_service,
    )

    assert created
    assert user.email == ID_TOKEN_PAYLOAD["email"]
    assert user.username == ID_TOKEN_PAYLOAD["username"]


@pytest.mark.django_db
def test_get_or_create_new_user_invalid_cached_jwks(oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    id_token = oac_jwt.id_token
    jwk = oac_jwt.jwk
    jwks = oac_jwt.jwks

    # regenerate key
    oac_jwt.kid = "foo"

    mock_jwks_service = Mock()
    mock_jwks_service.fetch.side_effect = [
        (oac_jwt.jwk, oac_jwt.jwks),
        (jwk, jwks),
    ]
    mock_jwks_service.save.return_value = None

    provider = DefaultUserProvider()

    user, created = provider.get_or_create(
        id_token,
        lookup_field="email",
        fetch_from_services=[mock_jwks_service, mock_jwks_service],
        save_by_service=mock_jwks_service,
    )

    assert created
    assert user.email == ID_TOKEN_PAYLOAD["email"]
    assert user.username == ID_TOKEN_PAYLOAD["username"]


@pytest.mark.django_db
def test_get_or_create_new_user_invalid_signature_error(oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    id_token = oac_jwt.id_token

    # regenerate key
    oac_jwt.kid = "foo"

    mock_jwks_service = Mock()
    mock_jwks_service.fetch.side_effect = [
        (None, None),
        (oac_jwt.jwk, oac_jwt.jwks),
    ]
    mock_jwks_service.save.return_value = None

    provider = DefaultUserProvider()

    with pytest.raises(InvalidSignatureError):
        provider.get_or_create(
            id_token,
            lookup_field="email",
            fetch_from_services=[mock_jwks_service, mock_jwks_service],
            save_by_service=mock_jwks_service,
        )


@pytest.mark.django_db
def test_get_or_create_new_user_insufficient_payload_error(oac_jwt):
    id_token_payload = copy(ID_TOKEN_PAYLOAD)
    del id_token_payload["email"]

    oac_jwt.kid = "foo"
    oac_jwt.id_token = id_token_payload

    mock_jwks_service = Mock()
    mock_jwks_service.fetch.return_value = oac_jwt.jwk, oac_jwt.jwks

    provider = DefaultUserProvider()

    with pytest.raises(InsufficientPayloadError):
        provider.get_or_create(
            oac_jwt.id_token,
            lookup_field="email",
            fetch_from_services=[mock_jwks_service, mock_jwks_service],
            save_by_service=mock_jwks_service,
        )


@pytest.mark.django_db
def test_get_or_create_existing_user(oac_jwt):
    UserModel.objects.create(**USER_PAYLOAD)

    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    mock_jwks_service = Mock()
    mock_jwks_service.fetch.return_value = oac_jwt.jwk, oac_jwt.jwks

    provider = DefaultUserProvider()

    user, created = provider.get_or_create(
        oac_jwt.id_token,
        lookup_field="email",
        fetch_from_services=[mock_jwks_service, mock_jwks_service],
        save_by_service=mock_jwks_service,
    )

    assert not created
    assert user.email == ID_TOKEN_PAYLOAD["email"]
    assert user.username == ID_TOKEN_PAYLOAD["username"]


@pytest.mark.django_db
def test_get_or_create_no_jwk_and_jwks(oac_jwt):
    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    mock_jwks_service = Mock()
    mock_jwks_service.fetch.side_effect = [
        (None, None),
        (None, None),
    ]
    mock_jwks_service.save.return_value = None

    provider = DefaultUserProvider()

    with pytest.raises(Exception):
        provider.get_or_create(
            oac_jwt.id_token,
            lookup_field="email",
            fetch_from_services=[mock_jwks_service, mock_jwks_service],
            save_by_service=mock_jwks_service,
        )
