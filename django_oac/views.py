from json.decoder import JSONDecodeError
from logging import Logger, LoggerAdapter, getLogger
from uuid import uuid4

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.handlers.wsgi import WSGIRequest
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views.decorators.http import require_GET
from ipware import get_client_ip
from jwcrypto.common import JWException
from jwt.exceptions import PyJWTError
from requests.exceptions import RequestException

from .decorators import populate_view_logger as populate_logger
from .exceptions import (
    ExpiredStateError,
    OACError,
    ProviderRequestError,
    ProviderResponseError,
)
from .logger import get_extra


@require_GET
def authenticate_view(request: WSGIRequest) -> HttpResponse:
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

    if not settings.OAC.get("authorize_uri"):
        logger.error("missing 'authorize_uri'")
        ret = render(
            request,
            "error.html",
            {"message": "App config is incomplete, cannot continue."},
            status=500,
        )
    else:
        ret = redirect(
            f"{settings.OAC['authorize_uri']}"
            f"?scope={settings.OAC.get('scope', 'openid')}"
            f"&client_id={settings.OAC.get('client_id', '')}"
            f"&redirect_uri={settings.OAC.get('redirect_uri', '')}"
            f"&state={state_str}"
            "&response_type=code"
        )
    return ret


@require_GET
@populate_logger
def callback_view(request: WSGIRequest, logger: Logger = None) -> HttpResponse:
    logger.info("callback request")

    try:
        user = authenticate(request)
    except ProviderRequestError as err:
        logger.error(f"raised django_oac.exceptions.ProviderRequestError: {err}")
        ret = render(request, "error.html", {"message": "Bad request."}, status=400)
    except ExpiredStateError:
        logger.info("state expired")
        ret = render(
            request,
            "error.html",
            {
                "redirect": reverse("django_oac:authenticate"),
                "message": "Logging attempt took too long, try again.",
            },
            status=400,
        )
    except KeyError as err:
        logger.error(f"configuration error, missing {err}")
        ret = render(
            request,
            "error.html",
            {"message": "App config is incomplete, cannot continue."},
            status=500,
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
            "error.html",
            {"message": "Something went wrong, cannot continue."},
            status=500,
        )
    else:
        if user:
            logger.info(f"user '{user.email}' authenticated")
            login(request, user, backend="django_oac.backends.OAuthClientBackend")
            ret = redirect("django_oac:profile")
        else:
            ret = render(request, "error.html", {"message": "Forbidden."}, status=403)

    request.session["OAC_STATE_TIMESTAMP"] = 0

    return ret


@login_required(login_url=reverse_lazy("django_oac:authenticate"))
@require_GET
@populate_logger
def logout_view(request: WSGIRequest, logger: Logger = None) -> HttpResponse:
    logger.info("logout request")

    token = request.user.token_set.last()

    ret = redirect("django_oac:profile")
    if token:
        try:
            token.revoke()
        except KeyError as err:
            logger.error(f"configuration error, missing {err}")
            ret = render(
                request,
                "error.html",
                {"message": "App config is incomplete, cannot continue."},
                status=500,
            )
        except ProviderResponseError as err:
            logger.error(f"raised django_oac.exceptions.ProviderResponseError: {err}")
            ret = render(
                request,
                "error.html",
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
def profile_view(request: WSGIRequest) -> JsonResponse:
    return JsonResponse(
        {
            field: getattr(request.user, field, "")
            for field in ("first_name", "last_name", "email", "username")
        }
    )
