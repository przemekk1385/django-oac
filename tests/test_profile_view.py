import json

from unittest.mock import Mock, patch

from django.shortcuts import reverse

from django_oac.views import profile_view


@patch("django_oac.views.logout")
def test_profile_view(rf):
    user = Mock()
    type(user).first_name = "spam"
    type(user).last_name = "eggs"
    type(user).email = "spam@eggs"
    type(user).username = ""

    request = rf.get(reverse("django_oac:profile"))
    request.session = {"OAC_STATE_STR": "test", "OAC_CLIENT_IP": "127.0.0.1"}
    request.user = user

    response = profile_view(request)

    assert 200 == response.status_code
    assert {
        "first_name": "spam",
        "last_name": "eggs",
        "email": "spam@eggs",
        "username": ""
    } == json.loads(response.content)
