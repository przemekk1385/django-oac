import pytest
from django.shortcuts import reverse


@pytest.mark.django_db
def test_authentication_endpoint(client):
    session = client.session
    session["OAC_STATE_STR"] = "test"
    session["OAC_CLIENT_IP"] = "127.0.0.1"
    session.save()

    response = client.get(reverse("django_oac:authenticate"))

    assert response.status_code == 302
