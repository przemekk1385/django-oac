from logging import LoggerAdapter, getLogger
from typing import Union
from urllib.parse import parse_qsl, urlparse
from uuid import uuid4

import pendulum
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http.request import HttpRequest
from django.utils import timezone

from .conf import settings as oac_settings
from .exceptions import ExpiredStateError, MismatchingStateError, ProviderRequestError
from .logger import get_extra
from .models import Token
from .stores import JWTPayloadStore

UserModel = get_user_model()


class OAuthClientBackend:
    @staticmethod
    def _parse_request_uri(request_uri: str):
        query_dict = dict(parse_qsl(urlparse(request_uri).query))

        if {"state", "code"}.difference(query_dict.keys()):
            raise ProviderRequestError(
                "missing one or both 'code', 'state' required query params"
            )

        return query_dict["code"], query_dict["state"]

    @staticmethod
    def _validate_state(
        session_state_str: str,
        request_state_str: str,
        sessions_state_timestamp: float,
        state_expires_in: int,
    ):
        if session_state_str != request_state_str:
            raise MismatchingStateError(
                "CSRF warning, mismatching request and response states"
            )
        if state_expires_in is not None and timezone.now() >= pendulum.from_timestamp(
            sessions_state_timestamp + state_expires_in, tz=settings.TIME_ZONE
        ):
            raise ExpiredStateError("state has expired")

    @staticmethod
    def get_user(primary_key: int) -> Union[UserModel, None]:
        try:
            user = UserModel.objects.get(pk=primary_key)
        except UserModel.DoesNotExist:
            user = None

        return user

    def authenticate(
        self, request: HttpRequest, username: str = None, password: str = None
    ) -> Union[UserModel, None]:
        # pylint: disable=unused-argument

        logger = LoggerAdapter(
            getLogger(__package__),
            get_extra(
                "backends.OAuthClientBackend",
                request.session["OAC_CLIENT_IP"],
                request.session["OAC_STATE_STR"],
            ),
        )

        request_uri = request.build_absolute_uri()

        code, request_state_str = self._parse_request_uri(request_uri)
        self._validate_state(
            request.session.get("OAC_STATE_STR"),
            request_state_str,
            request.session.get("OAC_STATE_TIMESTAMP", 0),
            oac_settings.STATE_EXPIRES_IN,
        )

        token, id_token = Token.remote.get(code)

        lookup_field = oac_settings.LOOKUP_FIELD
        required_payload_fields = set(oac_settings.REQUIRED_PAYLOAD_FIELDS)
        required_payload_fields.add(lookup_field)

        user_payload_store = JWTPayloadStore(required_payload_fields)
        user_payload = user_payload_store.get(id_token)

        # TODO:
        #  class for creating user

        try:
            user = UserModel.objects.get(
                **{lookup_field: user_payload.get(lookup_field)}
            )
        except UserModel.DoesNotExist:
            logger.info(
                "created new user '%s'", user_payload[lookup_field],
            )
            user = UserModel.objects.create(
                username=user_payload.get("username", uuid4().hex),
                **{field: user_payload[field] for field in required_payload_fields},
            )
        else:
            logger.info(
                "matched existing user '%s'", user_payload[lookup_field],
            )
            if user.token_set.exists():
                user.token_set.all().delete()

        token.user = user
        token.save()

        return user
