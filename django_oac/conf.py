from django.conf import LazySettings
from django.conf import settings as project_settings

from .exceptions import ConfigurationError

DEFAULTS = {
    "AUTHORIZE_URI": None,
    "TOKEN_URI": None,
    "REVOKE_URI": None,
    "REDIRECT_URI": None,
    "JWKS_URI": None,
    "CLIENT_ID": None,
    "CLIENT_SECRET": None,
    "SCOPE": "openid",
    "STATE_EXPIRES_IN": 300,
}


# pylint: disable=too-few-public-methods
class OACSettings:
    def __init__(
        self, project_setting: LazySettings, default_settings: dict = None
    ) -> None:
        self._project_settings = project_setting
        self._default_settings = default_settings or {}

    def __getattr__(self, item):
        if item not in self._default_settings:
            raise AttributeError(f"invalid setting '{item}'")

        ret = (
            getattr(self._project_settings, "OAC", {}).get(item)
            or getattr(self._project_settings, "OAC", {}).get(item.lower())
            or self._default_settings[item]
        )

        if not ret and item in [
            key for key, value in self._default_settings.items() if value is None
        ]:
            raise ConfigurationError(f"missing required setting '{item}'")

        return ret


settings = OACSettings(project_settings, DEFAULTS)
