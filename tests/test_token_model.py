from unittest.mock import patch

import pytest
import pendulum

from django.utils import timezone

from django_oac.exceptions import FailedRequest
from django_oac.models import Token

from .helpers import make_mock_response


@pytest.mark.django_db
def test_has_expired_property():
    payload = {
        "access_token": "foo",
        "refresh_token": "bar",
        "expires_in": 3600,
        "issued": pendulum.instance(timezone.now()).subtract(seconds=3601),
    }

    token = Token.objects.create(**payload)

    assert token.has_expired


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_refresh_method_failure(mock_request):
    token = Token.objects.create(
        access_token="foo",
        refresh_token="bar",
        expires_in=3600,
        issued=pendulum.instance(timezone.now()).subtract(seconds=3601),
    )
    mock_request.post.return_value = make_mock_response(400, {},)

    with pytest.raises(FailedRequest) as e_info:
        token.refresh()

    assert e_info.value.status_code == 400


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_refresh_method_succeeded(mock_request):
    token = Token.objects.create(
        access_token="foo",
        refresh_token="bar",
        expires_in=3600,
        issued=pendulum.instance(timezone.now()).subtract(seconds=3601),
    )
    mock_request.post.return_value = make_mock_response(
        200, {"access_token": "spam", "refresh_token": "eggs", "expires_in": 3600},
    )

    token.refresh()

    assert token.access_token == "spam"
    assert token.refresh_token == "eggs"
    assert token.expires_in == 3600
    assert not token.has_expired
