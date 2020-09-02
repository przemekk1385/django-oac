import json
from unittest.mock import Mock

from django.shortcuts import reverse

from django_oac.views import profile_view

from ..common import USER_PAYLOAD


# pylint: disable=invalid-name
def test_profile_view(rf):
    user = Mock()
    type(user).first_name = USER_PAYLOAD["first_name"]
    type(user).last_name = USER_PAYLOAD["last_name"]
    type(user).email = USER_PAYLOAD["email"]
    type(user).username = USER_PAYLOAD["username"]

    request = rf.get(reverse("django_oac:profile"))
    request.session = {"OAC_STATE_STR": "test", "OAC_CLIENT_IP": "127.0.0.1"}
    request.user = user

    response = profile_view(request)

    assert response.status_code == 200
    assert json.loads(response.content) == USER_PAYLOAD
