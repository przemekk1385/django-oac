from logging import getLogger
from typing import Tuple, Union

import pendulum
import requests
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone

from .conf import settings as oac_settings
from .exceptions import ProviderResponseError
from .helpers import get_missing_keys

UserModel = get_user_model()
logger = getLogger(__package__)


# pylint: disable=too-few-public-methods
class TokenRemoteManager:
    @staticmethod
    def _prepare_get_access_token_request_payload(code: str) -> dict:
        return {
            "grant_type": "authorization_code",
            "client_id": oac_settings.CLIENT_ID,
            "client_secret": oac_settings.CLIENT_SECRET,
            "code": code,
            "redirect_uri": oac_settings.REDIRECT_URI,
        }

    def get(self, code: str) -> Tuple["Token", Union[str, None]]:
        response = requests.post(
            oac_settings.TOKEN_URI,
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

        return (
            token,
            id_token,
        )


class Token(models.Model):

    access_token = models.TextField()
    refresh_token = models.TextField()
    expires_in = models.PositiveIntegerField(editable=False)
    user = models.ForeignKey(
        UserModel, blank=True, editable=False, null=True, on_delete=models.CASCADE
    )
    issued = models.DateTimeField(editable=False)

    remote = TokenRemoteManager()

    def __str__(self) -> str:
        return f"issued on {self.issued} for {self.user.username}"

    def _prepare_refresh_access_token_request_payload(self) -> dict:
        return {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": oac_settings.CLIENT_ID,
            "client_secret": oac_settings.CLIENT_SECRET,
        }

    def _prepare_revoke_refresh_token_request_payload(self) -> dict:
        return {
            "token": self.refresh_token,
            "token_type_hint": "refresh_token",
            "client_id": oac_settings.CLIENT_ID,
            "client_secret": oac_settings.CLIENT_SECRET,
        }

    @property
    def has_expired(self) -> bool:
        return timezone.now() >= pendulum.instance(self.issued).add(
            seconds=self.expires_in
        )

    def refresh(self) -> None:
        response = requests.post(
            oac_settings.TOKEN_URI,
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

    def revoke(self) -> None:
        response = requests.post(
            oac_settings.REVOKE_URI,
            self._prepare_revoke_refresh_token_request_payload(),
        )

        if response.status_code != 200:
            raise ProviderResponseError(
                "revoke refresh token request failed,"
                f" provider responded with code {response.status_code}",
            )
