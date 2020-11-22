from copy import copy
from unittest.mock import Mock

import jwt
import pytest
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.test import RequestFactory
from jwcrypto.jwk import JWK, JWKSet

from .common import QUERY_DICT, SESSION_DICT


class JWKTestHelper:
    __slots__ = ("_jwk", "_kid")

    def __init__(self):
        self._jwk = JWK.generate(kty="RSA", use="sig", alg="RS256")
        self._kid = None

    @property
    def jwk(self) -> str:
        return self._jwk.export_public()

    @property
    def jwk_set(self) -> str:
        jwk_set = JWKSet()
        jwk_set.add(self._jwk)
        return jwk_set.export(private_keys=False)

    @property
    def kid(self) -> str:
        return self._kid

    @kid.setter
    def kid(self, kid: str) -> None:
        self._kid = kid
        self._jwk = JWK.generate(kty="RSA", use="sig", alg="RS256", kid=kid)


class JWTTestHelper(JWKTestHelper):
    __slots__ = ("_payload",)

    def __init__(self):
        super().__init__()
        self._payload = None

    @property
    def id_token(self) -> str:
        return jwt.encode(
            self._payload,
            self._jwk.export_to_pem(private_key=True, password=None).decode("utf-8"),
            algorithm="RS256",
            headers={"alg": "RS256", "kid": self._kid},
        ).decode("utf-8")

    @id_token.setter
    def id_token(self, payload: dict) -> None:
        self._payload = payload


@pytest.fixture
def oac_mock_get_response() -> Mock:
    def make_get_response(_):
        get_response = Mock()
        get_response.return_value = None
        return get_response

    return make_get_response


@pytest.fixture
def oac_jwk() -> JWKTestHelper:
    return JWKTestHelper()


@pytest.fixture
def oac_jwt() -> JWTTestHelper:
    return JWTTestHelper()


@pytest.fixture
def oac_valid_get_request() -> RequestFactory:
    factory = RequestFactory()
    request = factory.get("foo", QUERY_DICT)
    request.session = copy(SESSION_DICT)
    request.user = AnonymousUser()
    return request


@pytest.yield_fixture(autouse=True)
def clear_django_cache() -> None:
    # setup
    yield
    # teardown
    cache.clear()
