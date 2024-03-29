from django.conf import LazySettings
from django.conf import settings as project_settings
from django.utils.module_loading import import_string

from .apps import DjangoOACConfig
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
    "LOOKUP_FIELD": "email",
    "TOKEN_PROVIDER_CLASS": (
        "django_oac.models_providers.token_provider.DefaultTokenProvider"
    ),
    "USER_PROVIDER_CLASS": (
        "django_oac.models_providers.user_provider.DefaultUserProvider"
    ),
}

IMPORT_STRINGS = (
    "TOKEN_PROVIDER_CLASS",
    "USER_PROVIDER_CLASS",
)

ALLOWED_NONES = ("STATE_EXPIRES_IN",)

APP_NAME = DjangoOACConfig.name
APP_VERBOSE_NAME = DjangoOACConfig.verbose_name


def import_from_string(dotted_path, setting_name):
    try:
        return import_string(dotted_path)
    except ImportError as e_info:
        raise ImportError(
            "Could not import '%s' for %s setting '%s'. %s: %s."
            % (
                dotted_path,
                APP_VERBOSE_NAME,
                setting_name,
                e_info.__class__.__name__,
                e_info,
            )
        ) from e_info


class OACSettings:
    def __init__(
        self,
        project_setting: LazySettings,
        default_settings: dict = None,
        import_strings: tuple = None,
    ) -> None:
        self._project_settings = project_setting
        self._default_settings = default_settings or {}
        self._import_strings = import_strings or ()

    def __getattr__(self, item):
        if item not in self._default_settings:
            raise AttributeError(f"invalid setting '{item}'")

        if item == "LOOKUP_FIELD":  # not yet configurable
            val = self._default_settings[item]
        else:
            val = (
                getattr(self._project_settings, "OAC", {}).get(item)
                or getattr(self._project_settings, "OAC", {}).get(item.lower())
                or self._default_settings[item]
            )

        if item in self._import_strings:
            ret = import_from_string(val, item)
        else:
            ret = val

        if ret is None and item not in ALLOWED_NONES:
            raise ConfigurationError(f"missing required setting '{item}'")

        return ret


settings = OACSettings(project_settings, DEFAULTS, IMPORT_STRINGS)
