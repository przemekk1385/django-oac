from logging import LoggerAdapter, getLogger
from typing import Union
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.http.request import HttpRequest

from .conf import settings as oac_settings
from .logger import get_extra
from .models import Token
from .stores import JWTPayloadStore

UserModel = get_user_model()


class OAuthClientBackend:
    @staticmethod
    def get_user(primary_key: int) -> Union[UserModel, None]:
        try:
            user = UserModel.objects.get(pk=primary_key)
        except UserModel.DoesNotExist:
            user = None

        return user

    @staticmethod
    def authenticate(
        request: HttpRequest,
        username: str = None,
        password: str = None,
        code: str = None,
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
                "matched existing user '%s'", user.email,
            )
            if user.token_set.exists():
                user.token_set.all().delete()

        token.user = user
        token.save()

        return user
