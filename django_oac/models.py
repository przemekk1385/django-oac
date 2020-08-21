import json
from typing import Tuple, Union
from uuid import uuid4

import jwt
import pendulum
import requests
from django.conf import settings
from django.contrib.auth.backends import UserModel
from django.db import models
from django.utils import timezone

from .exceptions import FailedRequest


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
            raise FailedRequest(
                "access token request failed,"
                f" provider responded with code {response.status_code}",
                response.status_code,
            )

        # TODO: handle token_type

        json_dict = response.json()
        id_token = json_dict.pop("id_token", None)

        return (
            Token(
                access_token=json_dict["access_token"],
                refresh_token=json_dict["refresh_token"],
                expires_in=json_dict["expires_in"],
                issued=timezone.now(),
            ),
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
            raise FailedRequest(
                "refresh access token request failed,"
                f" provider responded with code {response.status_code}",
                response.status_code,
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
        kid = jwt.get_unverified_header(id_token)["kid"]

        # TODO: caching

        response = requests.get(settings.OAC["jwks_uri"])

        if response.status_code != 200:
            raise FailedRequest(
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

        # TODO: configurable lookup field

        try:
            user = UserModel.objects.get(email=payload.get("email"))
        except UserModel.DoesNotExist:
            user = UserModel.objects.create(**payload)
        else:
            if user.token_set.exists():
                user.token_set.delete()

        return user


class User(UserModel):

    remote = UserRemoteManager()
