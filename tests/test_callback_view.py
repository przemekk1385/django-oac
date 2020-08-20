from unittest.mock import patch
import logging

from jwt.exceptions import PyJWTError, ExpiredSignatureError
import pytest

from django.shortcuts import reverse

from django_oac.exceptions import OACError, BadRequest, FailedRequest

logger = logging.getLogger(__name__)


@patch("django_oac.views.authenticate")
@pytest.mark.parametrize(
    "raised_exception,expected_message",
    [
        (PyJWTError, "foo"),
        (ExpiredSignatureError, "bar"),
        (OACError, "spam"),
        (BadRequest, "eggs"),
    ],
)
def test_callback_view(
    mock_authenticate, raised_exception, expected_message, client, caplog
):
    mock_authenticate.side_effect = raised_exception(expected_message)

    client.get(reverse("django_oac:callback"))

    for record in caplog.records:
        assert record.msg == f"{raised_exception.__name__}: {expected_message}"
