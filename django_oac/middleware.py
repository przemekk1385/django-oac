import logging
from typing import Callable, Type

from django.contrib.auth import logout
from django.core.handlers.wsgi import WSGIRequest
from django.http.response import HttpResponseBase

from .apps import DjangoOACConfig
from .exceptions import ProviderRequestError
from .models import Token

logger = logging.getLogger(DjangoOACConfig.name)


class OAuthClientMiddleware:
    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response

    def __call__(self, request: WSGIRequest) -> Type[HttpResponseBase]:
        user = request.user
        if user.is_authenticated:
            try:
                token = user.token_set.last()
            except Token.DoesNotExist:
                token = None

            if token and token.has_expired:
                try:
                    token.refresh()
                except ProviderRequestError as e:
                    logger.error(f"raised ProviderRequestError: {e}")
                    logout(request)
                else:
                    logger.info(f"access token for user '{user.email}' refreshed")

                if token.has_expired:
                    token.refresh()

        response = self.get_response(request)

        return response
