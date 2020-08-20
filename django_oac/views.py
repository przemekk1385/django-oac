from uuid import uuid4

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.core.handlers.wsgi import WSGIRequest
from django.http import HttpResponse
from django.shortcuts import redirect
from django.utils import timezone


def authenticate_view(request: WSGIRequest) -> HttpResponse:
    state_str = uuid4().hex
    request.session["OAC_STATE_STR"] = state_str
    request.session["OAC_STATE_TIMESTAMP"] = timezone.now().timestamp()
    return redirect(
        f"{settings.OAC.get('authorize_uri', '')}"
        f"?scope={settings.OAC.get('scope', '')}"
        f"&client_id={settings.OAC.get('client_id', '')}"
        f"&redirect_uri={settings.OAC.get('redirect_uri', '')}"
        f"&state={state_str}"
        "&response_type=code"
    )


def callback_view(request: WSGIRequest) -> HttpResponse:
    user = authenticate(request)
    if user:
        login(request, user, backend="django_oac.backends.OAuthClientBackend")
    return redirect("django_oac:test")


def logout_view(request: WSGIRequest) -> HttpResponse:
    pass


def test_view(request: WSGIRequest) -> HttpResponse:
    pass
