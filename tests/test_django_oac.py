from django.conf import settings
from toml import load

from django_oac import __version__


def test_version():
    v = (
        load(settings.BASE_DIR / "pyproject.toml")
        .get("tool", {})
        .get("poetry", {})
        .get("version", "0.0.0")
    )
    assert v == __version__
