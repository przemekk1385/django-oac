from django.conf import settings

USER_PAYLOAD = {
    "first_name": "spam",
    "last_name": "eggs",
    "email": "spam@eggs",
    "username": "spam.eggs",
}

ID_TOKEN_PAYLOAD = {
    **USER_PAYLOAD,
    "aud": settings.OAC["client_id"],
}
