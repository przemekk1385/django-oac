from logging import LoggerAdapter, getLogger
from typing import Callable, Type

from django.contrib.auth import logout
from django.core.handlers.wsgi import WSGIRequest
from django.http.response import HttpResponseBase

from .apps import DjangoOACConfig
from .exceptions import ProviderRequestError
from .models import Token


class OAuthClientMiddleware:
    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response

    def __call__(self, request: WSGIRequest) -> Type[HttpResponseBase]:
        logger = LoggerAdapter(
            getLogger(DjangoOACConfig.name),
            {
                "scope": "middleware",
                "ip_state": (
                    f"{request.session.get('OAC_CLIENT_IP', 'n/a')}"
                    f":{request.session.get('OAC_STATE_STR', 'n/a')}"
                ),
            },
        )
        user = request.user
        if user.is_authenticated:
            try:
                token = user.token_set.last()
            except Token.DoesNotExist:
                token = None

            if token and token.has_expired:
                logger.info(f"access token for user '{user.email}' has expired")
                try:
                    token.refresh()
                except ProviderRequestError as e:
                    logger.error(f"raised ProviderRequestError: {e}")
                    logout(request)
                else:
                    logger.info(
                        f"access token for user '{user.email}' has been refreshed"
                    )

        response = self.get_response(request)

        return response
