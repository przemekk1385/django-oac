from django.utils import timezone

from django_oac.conf import settings as oac_settings

TOKEN_PAYLOAD = {
    "access_token": "foo",
    "refresh_token": "bar",
    "expires_in": 3600,
}

USER_PAYLOAD = {
    "first_name": "spam",
    "last_name": "eggs",
    "email": "spam@eggs",
    "username": "spam.eggs",
}

ID_TOKEN_PAYLOAD = {
    **USER_PAYLOAD,
    "aud": oac_settings.CLIENT_ID,
}

QUERY_DICT = {"code": "foo", "state": "test"}

SESSION_DICT = {
    "OAC_STATE_STR": "test",
    "OAC_STATE_TIMESTAMP": timezone.now().timestamp(),
    "OAC_CLIENT_IP": "127.0.0.1",
}
