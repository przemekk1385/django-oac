from django_oac.conf import settings as oac_settings

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
