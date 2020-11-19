from abc import ABC, abstractmethod
from hashlib import sha1
from typing import Tuple

import requests
from django.core.cache import cache
from jwcrypto.jwk import JWKSet

from .conf import settings as oac_settings
from .exceptions import ProviderResponseError
from .helpers import get_missing_keys

CACHE_KEY = sha1(oac_settings.JWKS_URI.encode("utf-8")).hexdigest()


class OAuthRequestServiceBase(ABC):

    __slots__ = ()

    @abstractmethod
    def get_access_token(self, *args, **kwargs) -> dict:
        pass

    @abstractmethod
    def refresh_access_token(self, *args, **kwargs) -> dict:
        pass

    @abstractmethod
    def revoke_refresh_token(self, *args, **kwargs) -> None:
        pass


class OAuthRequestService(OAuthRequestServiceBase):
    @staticmethod
    def get_access_token(
        code: str,
        client_id: str = oac_settings.CLIENT_ID,
        client_secret: str = oac_settings.CLIENT_SECRET,
        redirect_uri: str = oac_settings.REDIRECT_URI,
        token_uri: str = oac_settings.TOKEN_URI,
    ) -> dict:
        payload = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }

        response = requests.post(token_uri, payload)

        if response.status_code != 200:
            raise ProviderResponseError(
                "access token request failed,"
                f" provider responded with code {response.status_code}"
            )

        # TODO:
        #  handle token_type

        json_dict = response.json()

        missing = get_missing_keys(
            {"access_token", "refresh_token", "expires_in", "id_token"},
            json_dict.keys(),
        )
        if missing:
            raise ProviderResponseError(
                f"provider response is missing required data: {missing}"
            )

        return json_dict

    @staticmethod
    def refresh_access_token(
        refresh_token: str,
        client_id: str = oac_settings.CLIENT_ID,
        client_secret: str = oac_settings.CLIENT_SECRET,
        token_uri: str = oac_settings.TOKEN_URI,
    ) -> dict:
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        response = requests.post(token_uri, payload)

        if response.status_code != 200:
            raise ProviderResponseError(
                "refresh access token request failed,"
                f" provider responded with code {response.status_code}",
            )

        return response.json()

    @staticmethod
    def revoke_refresh_token(
        refresh_token: str,
        client_id: str = oac_settings.CLIENT_ID,
        client_secret: str = oac_settings.CLIENT_SECRET,
        revoke_uri: str = oac_settings.REVOKE_URI,
    ) -> None:
        payload = {
            "token": refresh_token,
            "token_type_hint": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }

        response = requests.post(revoke_uri, payload)

        if response.status_code != 200:
            raise ProviderResponseError(
                "revoke refresh token request failed,"
                f" provider responded with code {response.status_code}",
            )


class JWKSServiceBase(ABC):

    __slots__ = ()

    @abstractmethod
    def clear(self, *args, **kwargs) -> None:
        pass

    def fetch(self, kid: str, jwks_json: str) -> Tuple[str, str]:
        jwk = None
        if jwks_json:
            jwk = JWKSet.from_json(jwks_json).get_key(kid).export_public()

        return jwk, jwks_json

    @abstractmethod
    def save(self, *args, **kwargs) -> None:
        pass


class CacheJWKSService(JWKSServiceBase):
    @staticmethod
    def clear() -> None:
        cache.clear()

    @staticmethod
    def fetch(kid: str, cache_key: str = CACHE_KEY, *args, **kwargs) -> Tuple[str, str]:
        return super(CacheJWKSService, CacheJWKSService).fetch(
            None, kid, cache.get(cache_key)
        )

    @staticmethod
    def save(jwks: str, cache_key: str = CACHE_KEY) -> None:
        cache.set(cache_key, jwks)


class OAuthJWKSService(JWKSServiceBase):
    @staticmethod
    def clear() -> None:
        raise NotImplementedError(f"cannot use 'clear' on OAuthJWKSService")

    @staticmethod
    def fetch(
        kid: str, jwks_uri: str = oac_settings.JWKS_URI, *args, **kwargs
    ) -> Tuple[str, str]:
        response = requests.get(jwks_uri)

        if response.status_code != 200:
            raise ProviderResponseError(
                "JSON Web Key Set request failed,"
                f" provider responded with code {response.status_code}"
            )

        return super(OAuthJWKSService, OAuthJWKSService).fetch(
            None, kid, response.content
        )

    @staticmethod
    def save() -> None:
        raise NotImplementedError(f"cannot use 'save' on OAuthJWKSService")
