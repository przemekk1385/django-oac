import logging
from unittest.mock import patch

import pytest
from django.shortcuts import reverse
from jwt.exceptions import ExpiredSignatureError, PyJWTError

from django_oac.exceptions import BadRequest, FailedRequest, OACError

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
        assert record.msg == f"raised '{raised_exception.__name__}: {expected_message}'"
