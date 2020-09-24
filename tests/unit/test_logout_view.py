from unittest.mock import Mock, patch

import pytest
from django.contrib.auth.models import AnonymousUser
from django.core.handlers.wsgi import WSGIRequest
from django.shortcuts import reverse

from django_oac.exceptions import ConfigurationError, ProviderResponseError
from django_oac.views import logout_view


def _logout(request: WSGIRequest):
    request.user = AnonymousUser()
    request.session.pop("_auth_user_backend", None)


# pylint: disable=invalid-name
@pytest.mark.parametrize(
    "exception", [ConfigurationError, ProviderResponseError],
)
@patch("django_oac.views.logout")
def test_logout_view_failure(mock_logout, exception, rf):
    token = Mock()
    token.revoke.side_effect = exception("foo")
    user = Mock()
    type(user).email = "spam@eggs"
    user.token_set.last.return_value = token

    mock_logout.return_value = None
    mock_logout.side_effect = _logout

    request = rf.get(reverse("django_oac:logout"))
    request.session = {"OAC_STATE_STR": "test", "OAC_CLIENT_IP": "127.0.0.1"}
    request.user = user

    response = logout_view(request)

    assert response.status_code == 500


# pylint: disable=invalid-name
@patch("django_oac.views.logout")
def test_logout_view_succeeded(mock_logout, rf):
    user = Mock()
    type(user).email = "spam@eggs"
    user.token_set.last.return_value = Mock()

    mock_logout.return_value = None
    mock_logout.side_effect = _logout

    request = rf.get(reverse("django_oac:logout"))
    request.session = {"OAC_STATE_STR": "test", "OAC_CLIENT_IP": "127.0.0.1"}
    request.user = user

    response = logout_view(request)

    assert response.status_code == 302
