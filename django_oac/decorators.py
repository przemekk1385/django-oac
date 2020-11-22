from functools import wraps
from logging import Logger, LoggerAdapter, getLogger
from pathlib import Path
from typing import Callable

import pendulum
from django.conf import settings
from django.http import HttpResponse
from django.http.request import HttpRequest
from django.shortcuts import render, reverse
from django.utils import timezone

from .apps import DjangoOACConfig
from .conf import settings as oac_settings
from .logger import get_extra

TEMPLATES_DIR = Path(DjangoOACConfig.name)


def _set_logger(scope: str, client_ip: str, state_str: str):
    return LoggerAdapter(
        getLogger(__package__), get_extra(scope, client_ip, state_str),
    )


def populate_view_logger(func) -> Callable:
    @wraps(func)
    def wrapper_populate_view_logger(request: HttpRequest) -> HttpResponse:
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
        instance: object, request: HttpRequest
    ) -> HttpResponse:
        logger = _set_logger(
            f"{func.__module__.split('.')[-1]}.{instance.__class__.__name__}",
            request.session.get("OAC_CLIENT_IP", "n/a"),
            request.session.get("OAC_STATE_STR", "n/a"),
        )
        return func(instance, request, logger)

    return wrapper_populate_method_logger


def validate_query_string(func) -> Callable:
    @wraps(func)
    def wrapper_validate_query_string(
        request: HttpRequest, logger: Logger = None
    ) -> HttpResponse:
        if not request.GET.get("code") or not request.GET.get("state"):
            err = "missing one or both 'code', 'state' required query params"
            if logger:
                logger.info(err)
            return render(
                request, TEMPLATES_DIR / "400.html", {"error_message": err}, status=400,
            )

        return func(request, logger) if logger else func(request)

    return wrapper_validate_query_string


def validate_state_expiration(func) -> Callable:
    @wraps(func)
    def wrapper_validate_state_expiration(
        request: HttpRequest, logger: Logger = None
    ) -> HttpResponse:
        state_expiration_datetime = pendulum.from_timestamp(
            request.session.get("OAC_STATE_TIMESTAMP", 0)
            + oac_settings.STATE_EXPIRES_IN,
            tz=settings.TIME_ZONE,
        )
        if (
            oac_settings.STATE_EXPIRES_IN is not None
            and timezone.now() >= state_expiration_datetime
        ):
            if logger:
                logger.info("state expired")
            return render(
                request,
                TEMPLATES_DIR / "400.html",
                {
                    "redirect_url": reverse("django_oac:authenticate"),
                    "redirect_name": "authentication site",
                    "error_message": "Logging attempt took too long, try again.",
                },
                status=400,
            )

        return func(request, logger) if logger else func(request)

    return wrapper_validate_state_expiration


def validate_state_matching(func) -> Callable:
    @wraps(func)
    def wrapper_validate_state_matching(
        request: HttpRequest, logger: Logger = None
    ) -> HttpResponse:
        if request.GET.get("state") != request.session.get("OAC_STATE_STR"):
            err = "CSRF warning, mismatching request and response states"
            if logger:
                logger.info(err)
            return render(
                request, TEMPLATES_DIR / "400.html", {"error_message": err}, status=400,
            )

        return func(request, logger) if logger else func(request)

    return wrapper_validate_state_matching
