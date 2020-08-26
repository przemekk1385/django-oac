import logging
from unittest.mock import Mock, patch

import pytest
from django.shortcuts import reverse
from jwt.exceptions import ExpiredSignatureError

from django_oac.apps import DjangoOACConfig
from django_oac.exceptions import (
    ExpiredStateError,
    ProviderRequestError,
    ProviderResponseError,
)
from django_oac.views import callback_view


@patch("django_oac.views.authenticate")
def test_callback_view_failure_expired_state_error(
    mock_authenticate, rf, caplog,
):
    mock_authenticate.side_effect = ExpiredStateError("foo")
    request = rf.get(reverse("django_oac:callback"))
    request.session = {}
    caplog.set_level(logging.ERROR, logger=DjangoOACConfig.name)

    response = callback_view(request)

    assert 400 == response.status_code
    assert not caplog.records


@pytest.mark.parametrize(
    "exception,message,expected_message,expected_status_code",
    [
        (ProviderRequestError, "foo", "raised ProviderRequestError: foo", 400),
        (KeyError, "baz", "configuration error, missing 'baz'", 500),
        (ProviderResponseError, "spam", "raised ProviderResponseError: spam", 500),
        (ExpiredSignatureError, "eggs", "raised ExpiredSignatureError: eggs", 500),
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
    request.session = {}

    caplog.set_level(logging.ERROR, logger=DjangoOACConfig.name)

    response = callback_view(request)

    assert expected_status_code == response.status_code
    assert expected_message == caplog.records[0].msg


@patch("django_oac.views.login")
@patch("django_oac.views.authenticate")
def test_callback_view_user_authenticated(mock_authenticate, mock_login, rf):
    mock_authenticate.return_value = Mock()
    mock_login.return_value = None

    request = rf.get(reverse("django_oac:callback"))
    request.session = {}

    response = callback_view(request)

    assert 302 == response.status_code


@patch("django_oac.views.authenticate")
def test_callback_view_user_not_authenticated(mock_authenticate, rf):
    mock_authenticate.return_value = None

    request = rf.get(reverse("django_oac:callback"))
    request.session = {}

    response = callback_view(request)

    assert 403 == response.status_code
