import logging
from uuid import uuid4

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.core.handlers.wsgi import WSGIRequest
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from ipware import get_client_ip
from jwt.exceptions import PyJWTError

from .apps import DjangoOACConfig
from .exceptions import ExpiredStateError, OACError, ProviderRequestError

logger = logging.getLogger(DjangoOACConfig.name)


def authenticate_view(request: WSGIRequest) -> HttpResponse:
    state_str = uuid4().hex
    client_ip, is_routable = get_client_ip(request)

    request.session["OAC_STATE_STR"] = state_str
    request.session["OAC_STATE_TIMESTAMP"] = timezone.now().timestamp()
    request.session["OAC_CLIENT_IP"] = client_ip or "unknown"

    logger.info(f"started login attempt from  {request.session['OAC_CLIENT_IP']}")

    if not settings.OAC.get("authorize_uri"):
        logger.error("missing 'authorize_uri'")
        return render(
            request,
            "error.html",
            {"message": "App config is incomplete, cannot continue."},
            status=500,
        )
    else:
        return redirect(
            f"{settings.OAC['authorize_uri']}"
            f"?scope={settings.OAC.get('scope', 'openid')}"
            f"&client_id={settings.OAC.get('client_id', '')}"
            f"&redirect_uri={settings.OAC.get('redirect_uri', '')}"
            f"&state={state_str}"
            "&response_type=code"
        )


def callback_view(request: WSGIRequest) -> HttpResponse:
    logger.info(f"callback for {request.session.get('OAC_CLIENT_IP', 'unset')}")

    try:
        user = authenticate(request)
    except ProviderRequestError as e:
        logger.error(f"raised ProviderRequestError: {e}")
        ret = render(request, "error.html", {"message": "Bad request."}, status=400,)
    except ExpiredStateError:
        # no need to log
        ret = render(
            request,
            "error.html",
            {
                "redirect": reverse("django_oac:authenticate"),
                "message": "Logging attempt took too long, try again.",
            },
            status=400,
        )
    except KeyError as e:
        logger.error(f"configuration error, missing {e}")
        ret = render(
            request,
            "error.html",
            {"message": "App config is incomplete, cannot continue."},
            status=500,
        )
    except (OACError, PyJWTError) as e:
        logger.error(f"raised {e.__class__.__name__}: {e}")
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
            ret = redirect("django_oac:test")
        else:
            ret = render(request, "error.html", {"message": "Forbidden."}, status=403,)

    return ret


def logout_view(request: WSGIRequest) -> HttpResponse:
    pass


def test_view(request: WSGIRequest) -> HttpResponse:
    return HttpResponse(str(request.user))
