import logging
from logging.handlers import RotatingFileHandler

from django.apps import AppConfig
from django.conf import settings


class DjangoOACConfig(AppConfig):
    name = "django_oac"
    verbose_name = "Django OAuth Client"

    def ready(self):
        from . import checks  # isort:skip

        log_dir = settings.BASE_DIR / "log"
        if not log_dir.is_dir():
            log_dir.mkdir(parents=True)
        logger = logging.getLogger(self.name)
        fh = RotatingFileHandler(
            log_dir / f"{self.name}.log", maxBytes=(5 * 1024 ** 2),
        )
        fh.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(fh)
