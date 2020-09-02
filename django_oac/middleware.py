from logging import Logger
from typing import Callable, Type

from django.contrib.auth import logout
from django.core.handlers.wsgi import WSGIRequest
from django.http.response import HttpResponseBase

from .decorators import populate_method_logger as populate_logger
from .exceptions import ProviderResponseError


# pylint: disable=too-few-public-methods
class OAuthClientMiddleware:
    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response

    @populate_logger
    def __call__(self, request: WSGIRequest, logger: Logger) -> Type[HttpResponseBase]:
        user = request.user
        if user.is_authenticated:
            token = user.token_set.last()

            if token and token.has_expired:
                logger.info(f"access token for user '{user.email}' has expired")
                try:
                    token.refresh()
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
