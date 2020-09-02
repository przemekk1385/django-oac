import json

import pytest
from django.contrib.auth import get_user_model
from django.shortcuts import reverse

UserModel = get_user_model()


@pytest.mark.django_db
def test_logout_endpoint(client):
    user = UserModel.objects.create(
        first_name="spam", last_name="eggs", email="spam@eggs", username="spam.eggs"
    )
    client.force_login(user, backend="django_oac.backends.OAuthClientBackend")

    session = client.session
    session["OAC_STATE_STR"] = "test"
    session["OAC_CLIENT_IP"] = "127.0.0.1"
    session.save()

    response = client.get(reverse("django_oac:logout"), follow=True)

    assert response.status_code == 200
    assert json.loads(response.content) == {
        "first_name": "",
        "last_name": "",
        "email": "",
        "username": "",
    }
