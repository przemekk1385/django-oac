from functools import wraps
from logging import LoggerAdapter, getLogger
from typing import Callable

from django.core.handlers.wsgi import WSGIRequest
from django.http import HttpResponse

from .logger import get_extra


def _set_logger(scope: str, client_ip: str, state_str: str):
    return LoggerAdapter(
        getLogger(__package__), get_extra(scope, client_ip, state_str),
    )


def populate_view_logger(func) -> Callable:
    @wraps(func)
    def wrapper_populate_view_logger(request: WSGIRequest) -> HttpResponse:
        logger = _set_logger(
            f"{func.__module__.split('.')[-1]}.{func.__name__}",
            request.session.get("OAC_CLIENT_IP", "n/a"),
            request.session.get("OAC_STATE_STR", "n/a"),
        )
        return func(request, logger)

    return wrapper_populate_view_logger


def populate_method_logger(func) -> Callable:
    @wraps(func)
    def wrapper_populate_method_logger(
        instance: object, request: WSGIRequest
    ) -> HttpResponse:
        logger = _set_logger(
            f"{func.__module__.split('.')[-1]}.{instance.__class__.__name__}",
            request.session.get("OAC_CLIENT_IP", "n/a"),
            request.session.get("OAC_STATE_STR", "n/a"),
        )
        return func(instance, request, logger)

    return wrapper_populate_method_logger
