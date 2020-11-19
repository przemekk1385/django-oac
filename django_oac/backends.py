from logging import LoggerAdapter, getLogger
from typing import Union

from django.contrib.auth import get_user_model
from django.http.request import HttpRequest

from .conf import settings as oac_settings
from .logger import get_extra
from .models_providers.token_provider import TokenProviderBase

TokenProvider = oac_settings.TOKEN_PROVIDER_CLASS
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
        token_provider: TokenProviderBase = TokenProvider(),
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

        token = token_provider.create(code)

        return token.user
