from typing import Union
from urllib.parse import parse_qsl, urlparse

import pendulum
from django.conf import settings
from django.contrib.auth.backends import BaseBackend, UserModel
from django.core.handlers.wsgi import WSGIRequest
from django.utils import timezone

from .exceptions import ExpiredStateError, MismatchingStateError, ProviderRequestError
from .models import Token, User


class OAuthClientBackend(BaseBackend):
    @staticmethod
    def _parse_request_uri(request_uri: str, state_str: str):
        query_dict = dict(parse_qsl(urlparse(request_uri).query))

        if {"state", "code"}.difference(query_dict.keys()):
            raise ProviderRequestError(
                "missing one or both 'code', 'state' required query params"
            )
        if state_str != query_dict["state"]:
            raise MismatchingStateError(
                "CSRF warning, mismatching request and response states"
            )

        return query_dict["code"]

    @staticmethod
    def get_user(pk: int) -> Union[UserModel, None]:
        try:
            user = UserModel.objects.get(pk=pk)
        except UserModel.DoesNotExist:
            user = None

        return user

    def authenticate(
        self, request: WSGIRequest, username: str = None, password: str = None
    ) -> Union[UserModel, None]:
        request_uri = request.build_absolute_uri()
        state_str = request.session.get("OAC_STATE_STR")
        state_timestamp = request.session.get("OAC_STATE_TIMESTAMP", 0)

        code = self._parse_request_uri(request_uri, state_str)

        # TODO: configurable state expiration time

        if timezone.now() >= pendulum.from_timestamp(
            state_timestamp + 300, tz=settings.TIME_ZONE
        ):
            raise ExpiredStateError("state has expired")

        token, id_token = Token.remote.get(code)

        user = User.remote.get_from_id_token(id_token)

        token.user = user
        token.save()

        return user
