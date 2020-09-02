from django.shortcuts import reverse

from django_oac.views import authenticate_view


# pylint: disable=invalid-name
def test_authenticate_view_failure(
    settings, rf,
):
    settings.OAC = {}
    request = rf.get(reverse("django_oac:authenticate"))
    request.session = {"OAC_STATE_STR": "test", "OAC_CLIENT_IP": "127.0.0.1"}

    response = authenticate_view(request)

    assert response.status_code == 500


# pylint: disable=invalid-name
def test_authenticate_view_succeeded(
    settings, rf,
):
    settings.OAC = {"authorize_uri": "https://www.example.com/"}
    request = rf.get(reverse("django_oac:authenticate"))
    request.session = {"OAC_STATE_STR": "test", "OAC_CLIENT_IP": "127.0.0.1"}

    response = authenticate_view(request)

    assert response.status_code == 302
