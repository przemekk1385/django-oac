from json.decoder import JSONDecodeError
from logging import Logger, LoggerAdapter, getLogger
from pathlib import Path
from uuid import uuid4

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.http.request import HttpRequest
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views.decorators.http import require_GET
from ipware import get_client_ip
from jwcrypto.common import JWException
from jwt.exceptions import PyJWTError
from requests.exceptions import RequestException

from .apps import DjangoOACConfig
from .conf import settings as oac_settings
from .decorators import populate_view_logger as populate_logger
from .exceptions import (
    ConfigurationError,
    ExpiredStateError,
    OACError,
    ProviderRequestError,
    ProviderResponseError,
)
from .logger import get_extra

TEMPLATES_DIR = Path(DjangoOACConfig.name)


@require_GET
def authenticate_view(request: HttpRequest) -> HttpResponse:
    state_str = uuid4().hex
    client_ip, _ = get_client_ip(request)

    if request.session.get("OAC_STATE_STR") != "test":
        request.session["OAC_STATE_STR"] = state_str
        request.session["OAC_STATE_TIMESTAMP"] = timezone.now().timestamp()
        request.session["OAC_CLIENT_IP"] = client_ip or "unknown"

    logger = LoggerAdapter(
        getLogger(__package__),
        get_extra(
            "views.authenticate_view",
            request.session["OAC_CLIENT_IP"],
            request.session["OAC_STATE_STR"],
        ),
    )
    logger.info("authentication request")

    try:
        ret = redirect(
            f"{oac_settings.AUTHORIZE_URI}"
            f"?scope=openid"
            f"&client_id={oac_settings.CLIENT_ID}"
            f"&redirect_uri={oac_settings.REDIRECT_URI}"
            f"&state={state_str}"
            "&response_type=code"
        )
    except ConfigurationError as err:
        logger.error(str(err))
        ret = render(
            request,
            TEMPLATES_DIR / "500.html",
            {"message": "App config is incomplete, cannot continue."},
            status=500,
        )
    return ret


@require_GET
@populate_logger
def callback_view(request: HttpRequest, logger: Logger = None) -> HttpResponse:
    logger.info("callback request")

    try:
        user = authenticate(request)
    except ConfigurationError as err:
        logger.error(str(err))
        ret = render(
            request,
            TEMPLATES_DIR / "error.html",
            {"message": "App config is incomplete, cannot continue."},
            status=500,
        )
    except ProviderRequestError as err:
        logger.error(f"raised django_oac.exceptions.ProviderRequestError: {err}")
        ret = render(
            request,
            TEMPLATES_DIR / "error.html",
            {"message": "Bad request."},
            status=400,
        )
    except ExpiredStateError:
        logger.info("state expired")
        ret = render(
            request,
            TEMPLATES_DIR / "error.html",
            {
                "redirect": reverse("django_oac:authenticate"),
                "message": "Logging attempt took too long, try again.",
            },
            status=400,
        )
    except (
        JSONDecodeError,
        JWException,
        OACError,
        PyJWTError,
        RequestException,
        TypeError,
        ValueError,
    ) as err:
        logger.error(
            f"raised {err.__class__.__module__}.{err.__class__.__name__}: {err}"
        )
        ret = render(
            request,
            TEMPLATES_DIR / "error.html",
            {"message": "Something went wrong, cannot continue."},
            status=500,
        )
    else:
        if user:
            logger.info(f"user '{user.email}' authenticated")
            login(request, user, backend="django_oac.backends.OAuthClientBackend")
            ret = redirect("django_oac:profile")
        else:
            ret = render(
                request,
                TEMPLATES_DIR / "error.html",
                {"message": "Forbidden."},
                status=403,
            )

    request.session["OAC_STATE_TIMESTAMP"] = 0

    return ret


@populate_logger
@login_required(login_url=reverse_lazy("django_oac:authenticate"))
@require_GET
def logout_view(request: HttpRequest, logger: Logger = None) -> HttpResponse:
    logger.info("logout request")

    token = request.user.token_set.last()

    ret = redirect("django_oac:profile")
    if token:
        try:
            token.revoke()
        except ConfigurationError as err:
            logger.error(str(err))
            ret = render(
                request,
                TEMPLATES_DIR / "500.html",
                {"message": "App config is incomplete, cannot continue."},
                status=500,
            )
        except ProviderResponseError as err:
            logger.error(f"raised django_oac.exceptions.ProviderResponseError: {err}")
            ret = render(
                request,
                TEMPLATES_DIR / "500.html",
                {"message": "Something went wrong, cannot continue."},
                status=500,
            )
        else:
            logger.info(
                f"refresh token for user '{request.user.email}' has been revoked"
            )
            token.delete()

    email = request.user.email
    logout(request)
    logger.info(f"user '{email}' logged out")

    return ret


@require_GET
def profile_view(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            field: getattr(request.user, field, "")
            for field in ("first_name", "last_name", "email", "username")
        }
    )
