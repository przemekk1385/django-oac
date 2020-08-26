from unittest.mock import Mock, patch

import pytest
from django.shortcuts import reverse

from django_oac.exceptions import ProviderResponseError
from django_oac.views import logout_view


@pytest.mark.parametrize(
    "exception,expected_message",
    [(ProviderResponseError, "foo"), (KeyError, "configuration error, missing 'baz'")],
)
@patch("django_oac.views.logout")
def test_logout_view_failure(mock_logout, exception, expected_message, rf):
    token = Mock()
    token.revoke.side_effect = exception("foo")
    user = Mock()
    user.token_set.last.return_value = token

    mock_logout.return_value = None

    request = rf.get(reverse("django_oac:logout"))
    request.session = {}
    request.user = user

    response = logout_view(request)

    assert 500 == response.status_code


@patch("django_oac.views.logout")
def test_authenticate_view_succeeded(mock_logout, rf):
    user = Mock()
    user.token_set.last.return_value = Mock()

    mock_logout.return_value = None

    request = rf.get(reverse("django_oac:logout"))
    request.session = {}
    request.user = user

    response = logout_view(request)

    assert 302 == response.status_code
