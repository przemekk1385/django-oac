from logging import Logger
from typing import Callable, Type

from django.contrib.auth import logout
from django.http.request import HttpRequest
from django.http.response import HttpResponseBase

from .conf import settings as oac_settings
from .decorators import populate_method_logger as populate_logger
from .exceptions import ProviderResponseError
from .models_providers.token_provider import TokenProviderBase

TokenProvider = oac_settings.TOKEN_PROVIDER_CLASS


class OAuthClientMiddleware:
    def __init__(
        self,
        get_response: Callable,
        token_provider: TokenProviderBase = TokenProvider(),
    ) -> None:
        self.get_response = get_response
        self.token_provider = token_provider

    @populate_logger
    def __call__(self, request: HttpRequest, logger: Logger) -> Type[HttpResponseBase]:
        user = request.user
        if user.is_authenticated:
            token = user.token_set.last()

            if token and token.has_expired:
                logger.info(f"access token for user '{user.email}' has expired")
                try:
                    self.token_provider.refresh(token)
                except ProviderResponseError as err:
                    logger.error(f"raised ProviderResponseError: {err}")
                    token.delete()
                    logout(request)
                else:
                    logger.info(
                        f"access token for user '{user.email}' has been refreshed"
                    )
            elif not token:
                logger.info(f"no access token found for user '{user.email}'")
            else:
                logger.debug(f"access token for user '{user.email}' is valid")

        response = self.get_response(request)

        return response
