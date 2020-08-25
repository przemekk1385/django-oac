import logging
from unittest.mock import patch

import pytest
from django.shortcuts import reverse
from jwt.exceptions import ExpiredSignatureError

from django_oac.apps import DjangoOACConfig
from django_oac.exceptions import (
    ExpiredStateError,
    ProviderRequestError,
    ProviderResponseError,
)

logger = logging.getLogger(DjangoOACConfig.name)


@patch("django_oac.views.authenticate")
@pytest.mark.parametrize(
    "exception,message,expected_message,expected_status_code",
    [
        (ProviderRequestError, "foo", "raised ProviderRequestError: foo", 400),
        (ExpiredStateError, "bar", None, 400),
        (KeyError, "baz", "configuration error, missing 'baz'", 500),
        (ProviderResponseError, "spam", "raised ProviderResponseError: spam", 500),
        (ExpiredSignatureError, "eggs", "raised ExpiredSignatureError: eggs", 500),
    ],
)
def test_callback_view(
    mock_authenticate,
    exception,
    message,
    expected_message,
    expected_status_code,
    client,
    caplog,
):
    mock_authenticate.side_effect = exception(message)

    response = client.get(reverse("django_oac:callback"))

    assert expected_status_code == response.status_code
    assert expected_message == getattr(
        next(
            (
                record
                for record in caplog.records
                if record.name == DjangoOACConfig.name and record.levelname == "ERROR"
            ),
            None,
        ),
        "msg",
        None,
    )
