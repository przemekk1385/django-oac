import json
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.shortcuts import reverse

UserModel = get_user_model()


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_authentication_endpoint(settings, client, oac_jwk):
    settings.OAC = {
        "authorize_uri": "http://www.example.com/",
        "token_uri": "http://www.example.com/",
        "revoke_uri": "http://www.example.com/",
        "jwks_uri": "http://www.example.com/",
        "client_id": "foo-bar-baz",
    }

    user = UserModel.objects.create(
        first_name="spam", last_name="eggs", email="spam@eggs", username="spam.eggs"
    )
    client.force_login(user, backend="django_oac.backends.OAuthClientBackend")

    response = client.get(reverse("django_oac:logout"), follow=True)

    assert 200 == response.status_code
    assert {
        "first_name": "",
        "last_name": "",
        "email": "",
        "username": "",
    } == json.loads(response.content)
