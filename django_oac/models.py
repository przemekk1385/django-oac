from uuid import uuid4
import json

import jwt
import pendulum
import requests

from django.conf import settings
from django.contrib.auth.backends import UserModel
from django.db import models
from django.utils import timezone

from .exceptions import RequestFailed


class TokenRemoteManager:
    @staticmethod
    def _prepare_access_token_request_payload(code: str) -> dict:
        return {
            "grant_type": "authorization_code",
            "client_id": settings.OAC.get("client_id", ""),
            "client_secret": settings.OAC.get("client_secret", ""),
            "code": code,
            "redirect_uri": settings.OAC.get("redirect_uri", ""),
        }

    def get(self, code: str) -> "Token":
        response = requests.post(
            settings.OAC.get("token_uri", ""),
            self._prepare_access_token_request_payload(code),
        )

        if response.status_code != 200:
            raise RequestFailed(
                "access token request failed,"
                f" provider responded with code {response.status_code}",
                response.status_code,
            )

        json_dict = response.json()
        # id_token = json_dict.pop("id_token", "")

        return Token(
            access_token=json_dict["access_token"],
            refresh_token=json_dict["refresh_token"],
            expires_in=json_dict["expires_in"],
            issued=timezone.now(),
        )


class Token(models.Model):

    access_token = models.TextField()
    refresh_token = models.TextField()
    expires_in = models.PositiveIntegerField()
    user = models.ForeignKey(UserModel, blank=True, null=True, on_delete=models.CASCADE)
    issued = models.DateTimeField()

    remote = TokenRemoteManager()

    @property
    def has_expired(self) -> bool:
        return timezone.now() >= pendulum.instance(self.issued).add(
            seconds=self.expires_in
        )


class UserRemoteManager:
    @staticmethod
    def get_from_id_token(id_token: str) -> UserModel:
        kid = jwt.get_unverified_header(id_token)["kid"]

        # TODO: caching

        response = requests.get(settings.OAC.get("jwks_uri", ""))

        if response.status_code != 200:
            raise RequestFailed(
                "jwks request failed,"
                f" provider responded with code {response.status_code}",
                response.status_code,
            )

        jwt_algorithm = getattr(
            jwt.algorithms, settings.OAC.get("jwt_algorithm", "RSAAlgorithm")
        )
        keys = {
            key["kid"]: (jwt_algorithm.from_jwk(json.dumps(key)), key["alg"])
            for key in response.json().get("keys", [])
        }
        key, alg = keys[kid]
        payload = {
            **{
                field: value
                for field, value in jwt.decode(
                    id_token,
                    audience=settings.OAC.get("client_id", ""),
                    key=key,
                    algorithms=[alg],
                ).items()
                if field in ("first_name", "last_name", "email")
            },
            "username": uuid4().hex,
        }

        instance, created = UserModel.objects.get_or_create(**payload)

        return instance


class User(UserModel):

    remote = UserRemoteManager()
