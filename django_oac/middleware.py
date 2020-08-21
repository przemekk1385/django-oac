from typing import Callable, Type
import logging

from django.contrib.auth import logout
from django.core.handlers.wsgi import WSGIRequest
from django.http.response import HttpResponseBase

from .apps import DjangoOACConfig
from .models import Token
from .exceptions import FailedRequest

logger = logging.getLogger(DjangoOACConfig.name)


class OAuthClientMiddleware:
    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response

    def __call__(self, request: WSGIRequest) -> Type[HttpResponseBase]:
        user = request.user
        if user.is_authenticated:
            try:
                token = Token.objects.get(user=user)
            except Token.DoesNotExist:
                token = None

            if token.has_expired:
                try:
                    token.refresh()
                except FailedRequest as e:
                    logger.error(f"raised 'FailedRequest: {e}'")
                    logout(request)
                else:
                    logger.info(f"access token for user '{user.email}' refreshed")

                if token.has_expired:
                    token.refresh()

        response = self.get_response(request)

        return response
