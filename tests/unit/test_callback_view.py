import logging
from unittest.mock import Mock, PropertyMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.handlers.wsgi import WSGIRequest
from django.shortcuts import reverse
from jwt.exceptions import ExpiredSignatureError

from django_oac.apps import DjangoOACConfig
from django_oac.exceptions import (
    ConfigurationError,
    ExpiredStateError,
    ProviderRequestError,
    ProviderResponseError,
)
from django_oac.views import callback_view

UserModel = get_user_model()


def _login(request: WSGIRequest, user: UserModel, backend: str = ""):
    request.user = user
    request.session["_auth_user_backend"] = backend


# pylint: disable=invalid-name
@patch("django_oac.views.authenticate")
def test_callback_view_failure_expired_state_error(
    mock_authenticate, rf, caplog,
):
    mock_authenticate.side_effect = ExpiredStateError("foo")

    request = rf.get(reverse("django_oac:callback"))
    request.session = {}
    request.user = AnonymousUser()

    caplog.set_level(logging.ERROR, logger=DjangoOACConfig.name)

    response = callback_view(request)

    assert response.status_code == 400
    assert not caplog.records


# pylint: disable=invalid-name, too-many-arguments
@pytest.mark.parametrize(
    "exception,message,expected_message,expected_status_code",
    [
        (
            ProviderRequestError,
            "foo",
            "raised django_oac.exceptions.ProviderRequestError: foo",
            400,
        ),
        (ConfigurationError, "bar", "bar", 500),
        (
            ProviderResponseError,
            "spam",
            "raised django_oac.exceptions.ProviderResponseError: spam",
            500,
        ),
        (
            ExpiredSignatureError,
            "eggs",
            "raised jwt.exceptions.ExpiredSignatureError: eggs",
            500,
        ),
    ],
)
@patch("django_oac.views.authenticate")
def test_callback_view_failure_other_exceptions(
    mock_authenticate,
    exception,
    message,
    expected_message,
    expected_status_code,
    rf,
    caplog,
):
    mock_authenticate.side_effect = exception(message)

    request = rf.get(reverse("django_oac:callback"))
    request.session = {"OAC_STATE_STR": "test", "OAC_CLIENT_IP": "127.0.0.1"}
    request.user = AnonymousUser()

    caplog.set_level(logging.ERROR, logger=DjangoOACConfig.name)

    response = callback_view(request)

    assert response.status_code == expected_status_code
    assert caplog.records[0].msg == expected_message


# pylint: disable=invalid-name
@patch("django_oac.views.login")
@patch("django_oac.views.authenticate")
def test_callback_view_user_authenticated(mock_authenticate, mock_login, rf):
    user = Mock()
    type(user).email = PropertyMock(return_value="spam@eggs")

    mock_authenticate.return_value = user
    mock_login.return_value = None
    mock_login.side_effect = _login

    request = rf.get(reverse("django_oac:callback"))
    request.session = {"OAC_STATE_STR": "test", "OAC_CLIENT_IP": "127.0.0.1"}
    request.user = AnonymousUser()

    response = callback_view(request)

    assert response.status_code == 302


# pylint: disable=invalid-name
@patch("django_oac.views.authenticate")
def test_callback_view_user_not_authenticated(mock_authenticate, rf):
    mock_authenticate.return_value = None

    request = rf.get(reverse("django_oac:callback"))
    request.session = {"OAC_STATE_STR": "test", "OAC_CLIENT_IP": "127.0.0.1"}
    request.user = AnonymousUser()

    response = callback_view(request)

    assert response.status_code == 403
