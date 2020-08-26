from django.shortcuts import reverse

from django_oac.views import authenticate_view


def test_authenticate_view_failure(
    settings, rf,
):
    settings.OAC = {}
    request = rf.get(reverse("django_oac:authenticate"))
    request.session = {}

    response = authenticate_view(request)

    assert 500 == response.status_code


def test_authenticate_view_succeeded(
    settings, rf,
):
    settings.OAC = {"authorize_uri": "https://www.example.com/"}
    request = rf.get(reverse("django_oac:authenticate"))
    request.session = {}

    response = authenticate_view(request)

    assert 302 == response.status_code
