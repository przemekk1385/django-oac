from unittest.mock import MagicMock, PropertyMock
from uuid import uuid4

import pytest
from django.utils import timezone


@pytest.fixture
def oac_mock_user() -> MagicMock:
    user = MagicMock()
    for attr, value in [
        ("first_name", "spam"),
        ("last_name", "eggs"),
        ("email", "spam@eggs"),
        ("username", uuid4().hex),
    ]:
        setattr(type(user), attr, PropertyMock(return_value=value))

    return user


@pytest.fixture
def oac_mock_token() -> MagicMock:
    token = MagicMock()
    for attr, value in [
        ("access_token", "foo"),
        ("refresh_token", "bar"),
        ("expires_in", 3600),
        ("issued", timezone.now()),
        ("has_expired", False),
    ]:
        setattr(type(token), attr, PropertyMock(return_value=value))
    for obj, attr, value in [
        (token.delete, "return_value", None),
        (token.refresh, "return_value", None),
        (token.revoke, "return_value", None),
    ]:
        setattr(obj, attr, value)

    return token


@pytest.fixture
def get_response() -> MagicMock:
    def make_get_response(*args):
        get_response = MagicMock()
        get_response.return_value = None
        return get_response

    return make_get_response
