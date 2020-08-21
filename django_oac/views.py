import logging
from uuid import uuid4

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.core.handlers.wsgi import WSGIRequest
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from jwt.exceptions import PyJWTError

from .apps import DjangoOACConfig
from .exceptions import OACError

logger = logging.getLogger(DjangoOACConfig.name)


def authenticate_view(request: WSGIRequest) -> HttpResponse:
    state_str = uuid4().hex
    request.session["OAC_STATE_STR"] = state_str
    request.session["OAC_STATE_TIMESTAMP"] = timezone.now().timestamp()

    if not settings.OAC.get('authorize_uri'):
        logger.error("missing 'authorize_uri'")
        return render(request, "error.html", {"err": "config"})
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
    try:
        user = authenticate(request)
    except KeyError as e:
        logger.error(f"missing {e}")
        return render(request, "error.html", {"err": "config"})
    except (OACError, PyJWTError) as e:
        logger.error(f"raised '{e.__class__.__name__}: {e}'")
        return render(request, "error.html", {"redirect": reverse("django_oac:authenticate")})
    else:
        if user:
            logger.info(f"user '{user.email}' authenticated")
            login(request, user, backend="django_oac.backends.OAuthClientBackend")
        else:
            raise HttpResponseForbidden()

    return redirect("django_oac:test")


def logout_view(request: WSGIRequest) -> HttpResponse:
    pass


def test_view(request: WSGIRequest) -> HttpResponse:
    return HttpResponse(str(request.user))
