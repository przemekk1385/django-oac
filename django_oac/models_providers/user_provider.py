from abc import ABC, abstractmethod
from hashlib import sha1
from logging import getLogger
from typing import List, Tuple
from uuid import uuid4

import jwt
from django.contrib.auth import get_user_model
from jwcrypto.jwk import JWKSet
from jwt.exceptions import InvalidSignatureError

from ..conf import settings as oac_settings
from ..exceptions import InsufficientPayloadError
from ..helpers import get_missing_keys
from ..logger import get_extra
from ..services import CacheJWKSService, JWKSServiceBase, OAuthJWKSService

logger = getLogger(__package__)
UserModel = get_user_model()


class UserProviderBase(ABC):
    @abstractmethod
    def get_or_create(self, *args, **kwargs) -> Tuple[UserModel, bool]:
        pass


class DefaultUserProvider(UserProviderBase):
    def _services_fetch(self, kid: str, jwks_services: List[JWKSServiceBase]):
        for i, service in enumerate(jwks_services):
            jwk, jwks = service.fetch(kid)
            if jwk:
                return jwk, jwks, not bool(i)
        return 3 * [None]

    def get_or_create(
        self,
        id_token: str,
        lookup_field: str = oac_settings.LOOKUP_FIELD,
        cache_jwks_service: JWKSServiceBase = CacheJWKSService(),
        oauth_jwks_service: JWKSServiceBase = OAuthJWKSService(),
    ) -> Tuple[UserModel, bool]:
        kid = jwt.get_unverified_header(id_token).get("kid", None)

        jwk, jwks, from_cache = self._services_fetch(
            kid, [cache_jwks_service, oauth_jwks_service]
        )

        kwargs = {
            "audience": oac_settings.CLIENT_ID,
            "key": jwt.algorithms.RSAAlgorithm.from_jwk(jwk),
            "algorithms": ["RS256"],
            "leeway": 30,
        }

        try:
            data = jwt.decode(id_token, **kwargs)
        except InvalidSignatureError as e_info:
            if from_cache:
                jwk, jwks = oauth_jwks_service.fetch(kid)
                kwargs.update({"key": jwt.algorithms.RSAAlgorithm.from_jwk(jwk)})
                data = jwt.decode(id_token, **kwargs)
                cache_jwks_service.save(jwks)
            else:
                raise InvalidSignatureError(e_info)
        else:
            if not from_cache:
                cache_jwks_service.save(jwks)

        missing = get_missing_keys({"first_name", "last_name", "email"}, data.keys())
        if missing:
            raise InsufficientPayloadError(
                f"payload is missing required data: {missing}"
            )

        created = False
        lookup_value = data.get(lookup_field)

        try:
            instance = UserModel.objects.get(**{lookup_field: lookup_value})
        except UserModel.DoesNotExist:
            instance = UserModel.objects.create(
                first_name=data.get("first_name", ""),
                last_name=data.get("last_name", ""),
                email=data.get("email"),
                username=data.get("username", uuid4().hex),
            )
            created = True
            logger.info(
                f"created new user '{lookup_value}'",
                extra=get_extra(f"{__package__}.{self.__class__.__name__}"),
            )
        else:
            logger.info(
                f"got existing user '{lookup_value}'",
                extra=get_extra(f"{__package__}.{self.__class__.__name__}"),
            )

        return instance, created
