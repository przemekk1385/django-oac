import logging
from unittest.mock import Mock, PropertyMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.handlers.wsgi import WSGIRequest
from jwt.exceptions import ExpiredSignatureError

from django_oac.apps import DjangoOACConfig
from django_oac.exceptions import ConfigurationError, ProviderResponseError
from django_oac.views import callback_view

UserModel = get_user_model()


def _login(request: WSGIRequest, user: UserModel, backend: str = ""):
    request.user = user
    request.session["_auth_user_backend"] = backend


# pylint: disable=invalid-name, too-many-arguments
@pytest.mark.parametrize(
    "exception,message,expected_message,expected_status_code",
    [
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
    caplog,
    oac_valid_get_request,
):
    mock_authenticate.side_effect = exception(message)

    caplog.set_level(logging.ERROR, logger=DjangoOACConfig.name)

    response = callback_view(oac_valid_get_request)

    assert response.status_code == expected_status_code
    assert caplog.records[0].msg == expected_message


@patch("django_oac.views.login")
@patch("django_oac.views.authenticate")
def test_callback_view_user_authenticated(
    mock_authenticate, mock_login, oac_valid_get_request
):
    user = Mock()
    type(user).email = PropertyMock(return_value="spam@eggs")

    mock_authenticate.return_value = user
    mock_login.return_value = None
    mock_login.side_effect = _login

    response = callback_view(oac_valid_get_request)

    assert response.status_code == 302


@patch("django_oac.views.authenticate")
def test_callback_view_user_not_authenticated(mock_authenticate, oac_valid_get_request):
    mock_authenticate.return_value = None

    response = callback_view(oac_valid_get_request)

    assert response.status_code == 403
