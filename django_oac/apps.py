from django.apps import AppConfig
from django.conf import settings


class DjangoOACConfig(AppConfig):
    name = "django_oac"
    verbose_name = "Django OAuth Client"

    def ready(self):
        from .checks import (  # noqa: F401
            settings_oac_attr_check,
            settings_oac_keys_check,
            settings_oac_uris_check,
        )
        from .logger import set_logger

        set_logger(settings.BASE_DIR / "log")
