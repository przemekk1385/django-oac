from abc import ABC
from hashlib import sha1
from logging import getLogger
from typing import Type

import jwt
import requests
from django.core.cache import cache
from jwcrypto.jwk import JWKSet
from jwt.exceptions import InvalidSignatureError

from .conf import settings as oac_settings
from .exceptions import (
    InsufficientPayloadError,
    KeyNotFoundError,
    ProviderResponseError,
)
from .helpers import get_missing_keys
from .logger import get_extra

logger = getLogger(__package__)


# pylint: disable=too-few-public-methods
class DataStore(ABC):

    __slots__ = ()


# pylint: disable=too-few-public-methods
class JWKStore(DataStore):

    __slots__ = ("_calls_counter", "_key", "_uri")

    def __init__(self, uri: str = "") -> None:
        self._calls_counter = 0
        self._key = sha1(uri.encode("utf-8")).hexdigest()
        self._uri = uri

    def _get_cached(self) -> str:
        ret = cache.get(self._key)

        if ret:
            logger.info(
                "found cached JSON Web Key Set for '%s'",
                self._uri,
                extra=get_extra(f"{__package__}.{self.__class__.__name__}"),
            )

        return ret

    def _get_from_uri(self) -> str:
        response = requests.get(self._uri)

        if response.status_code != 200:
            raise ProviderResponseError(
                "JSON Web Key Set request failed,"
                f" provider responded with code {response.status_code}"
            )

        logger.info(
            "got JSON Web Key Set for '%s'",
            self._uri,
            extra=get_extra(f"{__package__}.{self.__class__.__name__}"),
        )

        return response.content

    def _save_in_cache(self, jwk_set_json: str) -> None:
        cache.set(self._key, jwk_set_json)
        logger.info(
            "JSON Web Key Set for '%s' saved in cache",
            self._uri,
            extra=get_extra(f"{__package__}.{self.__class__.__name__}"),
        )

    def get(self, kid: str) -> str:
        jwk_set_json = self._get_cached()

        if jwk_set_json is None or self._calls_counter:
            jwk_set_json = self._get_from_uri()

        key = JWKSet.from_json(jwk_set_json).get_key(kid)

        self._save_in_cache(jwk_set_json)
        self._calls_counter += 1

        if not key:
            raise KeyNotFoundError(f"key '{kid}' not found")

        return key.export()


# pylint: disable=too-few-public-methods
class JWTPayloadStore(DataStore):

    __slots__ = ("_jwk_store", "_required_fields")

    def __init__(
        self,
        required_fields: list = None,
        jwk_store: Type[DataStore] = JWKStore(oac_settings.JWKS_URI),
    ) -> None:
        self._jwk_store = jwk_store
        self._required_fields = required_fields or []

    def get(self, id_token: str) -> dict:
        kid = jwt.get_unverified_header(id_token).get("kid", None)

        kwargs = {
            "audience": oac_settings.CLIENT_ID,
            "key": jwt.algorithms.RSAAlgorithm.from_jwk(self._jwk_store.get(kid)),
            "algorithms": ["RS256"],
        }
        try:
            ret = jwt.decode(id_token, **kwargs,)
        except InvalidSignatureError:
            kwargs.update(
                {"key": jwt.algorithms.RSAAlgorithm.from_jwk(self._jwk_store.get(kid))}
            )
            ret = jwt.decode(id_token, **kwargs)

        missing = get_missing_keys(set(self._required_fields), ret.keys())
        if missing:
            raise InsufficientPayloadError(
                f"payload is missing required data: {missing}"
            )

        return ret
