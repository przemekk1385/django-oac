import json
import logging
from typing import Callable, Tuple, Union
from uuid import uuid4

import jwt
import pendulum
import requests
from django.conf import settings
from django.contrib.auth.backends import UserModel
from django.db import models
from django.utils import timezone

from .apps import DjangoOACConfig
from .exceptions import InsufficientPayloadError, MissingKtyError, ProviderResponseError

logger = logging.getLogger(DjangoOACConfig.name)
get_missing_keys: Callable[
    [set, Union[list, set, tuple]], str
] = lambda required, given: ", ".join(
    reversed(list(map(lambda key: f"'{key}'", required.difference(given))))
)


class TokenRemoteManager:
    @staticmethod
    def _prepare_get_access_token_request_payload(code: str) -> dict:
        return {
            "grant_type": "authorization_code",
            "client_id": settings.OAC.get("client_id", ""),
            "client_secret": settings.OAC.get("client_secret", ""),
            "code": code,
            "redirect_uri": settings.OAC.get("redirect_uri", ""),
        }

    def get(self, code: str) -> Tuple["Token", Union[str, None]]:
        response = requests.post(
            settings.OAC["token_uri"],
            self._prepare_get_access_token_request_payload(code),
        )

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

        id_token = json_dict.pop("id_token")
        token = Token(
            access_token=json_dict["access_token"],
            refresh_token=json_dict["refresh_token"],
            expires_in=json_dict["expires_in"],
            issued=timezone.now(),
        )

        logger.info(f"got access token and id token")

        return (
            token,
            id_token,
        )


class Token(models.Model):

    access_token = models.TextField()
    refresh_token = models.TextField()
    expires_in = models.PositiveIntegerField()
    user = models.ForeignKey(UserModel, blank=True, null=True, on_delete=models.CASCADE)
    issued = models.DateTimeField()

    remote = TokenRemoteManager()

    def _prepare_refresh_access_token_request_payload(self) -> dict:
        return {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": settings.OAC.get("client_id", ""),
            "client_secret": settings.OAC.get("client_secret", ""),
        }

    @property
    def has_expired(self) -> bool:
        return timezone.now() >= pendulum.instance(self.issued).add(
            seconds=self.expires_in
        )

    def refresh(self) -> None:
        response = requests.post(
            settings.OAC["token_uri"],
            self._prepare_refresh_access_token_request_payload(),
        )

        if response.status_code != 200:
            raise ProviderResponseError(
                "refresh access token request failed,"
                f" provider responded with code {response.status_code}",
            )

        json_dict = response.json()

        self.access_token = json_dict.get("access_token", self.access_token)
        self.refresh_token = json_dict.get("refresh_token", self.refresh_token)
        self.expires_in = json_dict.get("expires_in", self.expires_in)
        self.issued = timezone.now()
        self.save()


class UserRemoteManager:
    @staticmethod
    def get_from_id_token(id_token: str) -> UserModel:
        kid = jwt.get_unverified_header(id_token).get("kid", None)

        # TODO:
        #  caching

        response = requests.get(settings.OAC["jwks_uri"])

        if response.status_code != 200:
            raise ProviderResponseError(
                "jwks request failed,"
                f" provider responded with code {response.status_code}"
            )

        # TODO:
        #  auto-pick algorithm

        try:
            key = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(
                    next(
                        (
                            k
                            for k in response.json().get("keys", [{}])
                            if k.get("kid") == kid and k["kty"] == "RSA"
                        ),
                        {},
                    )
                )
            )
        except KeyError:
            raise MissingKtyError("missing JSON Web Key Type")

        payload = jwt.decode(
            id_token,
            audience=settings.OAC.get("client_id", ""),
            key=key,
            algorithms=["RS256"],
        )

        missing = get_missing_keys({"first_name", "last_name", "email"}, payload.keys())
        if missing:
            raise InsufficientPayloadError(
                f"payload is missing required data: {missing}"
            )

        # TODO:
        #  configurable lookup field
        #  class for creating user

        try:
            user = UserModel.objects.get(email=payload.get("email"))
        except UserModel.DoesNotExist:
            logger.info(f"created new user {payload['email']}")
            user = UserModel.objects.create(
                first_name=payload["first_name"],
                last_name=payload["last_name"],
                email=payload["email"],
                username=uuid4().hex,
            )
        else:
            logger.info(f"matched existing user {payload['email']}")
            if user.token_set.exists():
                user.token_set.delete()

        return user


class User(UserModel):

    remote = UserRemoteManager()
