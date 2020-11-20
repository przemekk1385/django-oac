from abc import ABC, abstractmethod
from logging import getLogger
from typing import List, Tuple, Union
from uuid import uuid4

import jwt
from django.contrib.auth import get_user_model
from jwt.exceptions import InvalidSignatureError

from ..conf import settings as oac_settings
from ..exceptions import InsufficientPayloadError
from ..helpers import get_missing_keys
from ..logger import get_extra
from ..services import CacheJWKSService, JWKSServiceBase, OAuthJWKSService

logger = getLogger(__package__)
UserModel = get_user_model()


# pylint: disable=too-few-public-methods
class UserProviderBase(ABC):
    @abstractmethod
    def get_or_create(
        self, id_token: str, lookup_field: str, **kwargs
    ) -> Tuple[UserModel, bool]:
        pass


class DefaultUserProvider(UserProviderBase):
    @staticmethod
    def fetch_jwks_from_services(
        kid: str,
        slice_starting_index: int = 0,
        jwks_services: List[JWKSServiceBase] = None,
    ) -> Union[Tuple[str, str, bool], Tuple[None, None, None]]:
        jwks_services = jwks_services or [
            CacheJWKSService(),
            OAuthJWKSService(),
        ]

        for i, service in enumerate(jwks_services[slice_starting_index:]):
            jwk, jwks = service.fetch(kid)
            if jwk:
                return jwk, jwks, not bool(i)
        return None, None, None

    @staticmethod
    def save_jwks_by_service(jwks: str, jwks_service: JWKSServiceBase = None):
        jwks_service = jwks_service or CacheJWKSService()
        jwks_service.save(jwks)

    def decode_id_token(self, id_token: str, **kwargs):
        kid = jwt.get_unverified_header(id_token).get("kid", None)

        jwk, jwks, from_cache = self.fetch_jwks_from_services(
            kid, jwks_services=kwargs.get("fetch_from_services")
        )

        jwt_decode_kwargs = {
            "audience": oac_settings.CLIENT_ID,
            "key": jwt.algorithms.RSAAlgorithm.from_jwk(jwk),
            "algorithms": ["RS256"],
            "leeway": 30,
        }

        try:
            data = jwt.decode(id_token, **jwt_decode_kwargs)
        except InvalidSignatureError as e_info:
            if from_cache:
                jwk, jwks, _ = self.fetch_jwks_from_services(
                    kid, 1, kwargs.get("fetch_from_services")
                )
                jwt_decode_kwargs.update(
                    {"key": jwt.algorithms.RSAAlgorithm.from_jwk(jwk)}
                )
                data = jwt.decode(id_token, **jwt_decode_kwargs)
                self.save_jwks_by_service(jwks, kwargs.get("save_by_service"))
            else:
                raise InvalidSignatureError from e_info
        else:
            if not from_cache:
                self.save_jwks_by_service(jwks, kwargs.get("save_by_service"))

        return data

    def get_or_create(
        self, id_token: str, lookup_field: str = oac_settings.LOOKUP_FIELD, **kwargs
    ) -> Tuple[UserModel, bool]:
        data = self.decode_id_token(id_token, **kwargs)

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
                "created new user '%s'",
                lookup_value,
                extra=get_extra(f"{__package__}.{self.__class__.__name__}"),
            )
        else:
            logger.info(
                "got existing user '%s'",
                lookup_value,
                extra=get_extra(f"{__package__}.{self.__class__.__name__}"),
            )

        return instance, created
