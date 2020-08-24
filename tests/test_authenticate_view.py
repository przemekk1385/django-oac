from unittest.mock import patch

import pytest
from django.shortcuts import reverse


@pytest.mark.django_db
@patch("django_oac.views.settings.OAC")
def test_authenticate_view(
    mock_settings, client,
):
    mock_settings.get.return_value = None

    response = client.get(reverse("django_oac:authenticate"))

    assert 500 == response.status_code
