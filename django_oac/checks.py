from urllib.parse import urlparse

from django.conf import settings
from django.core.checks import Error, register


@register
def settings_oac_attr_check(app_configs, **kwargs):
    errors = []
    if not hasattr(settings, "OAC"):
        errors.append(
            Error(
                "missing settings.OAC",
                hint=(
                    "add OAC dictionary with the following keys: 'token_uri',"
                    " 'revoke_uri', 'redirect_uri', 'jwks_uri' to Django settings file"
                ),
                id="django_oac.E001",
            )
        )
    elif not isinstance(settings.OAC, dict):
        errors.append(
            Error("settings.OAC should be dict instance", id="django_oac.E002",)
        )
    return errors


@register
def settings_oac_keys_check(app_configs, **kwargs):
    errors = []
    if hasattr(settings, "OAC") and isinstance(settings.OAC, dict):
        for key in {
            "authorize_uri",
            "token_uri",
            "revoke_uri",
            "redirect_uri",
            "jwks_uri",
        }.difference(settings.OAC.keys()):
            errors.append(
                Error(
                    f"required settings.OAC key '{key}' is missing",
                    id="django_oac.E003",
                )
            )
    return errors


@register
def settings_oac_uris_check(app_configs, **kwargs):
    errors = []
    if hasattr(settings, "OAC") and isinstance(settings.OAC, dict):
        for key in [
            k
            for k in settings.OAC.keys()
            if k
            in ("authorize_uri", "token_uri", "revoke_uri", "redirect_uri", "jwks_uri",)
        ]:
            parse_result = urlparse(settings.OAC[key])
            if not parse_result.scheme or not parse_result.netloc:
                errors.append(
                    Error(
                        f"key '{key}' seems to store invalid URI", id="django_oac.E004",
                    )
                )
    return errors


# TODO:
#  check environmental variables 'client_id', 'client_secret'
#  check middleware and authentication backend
