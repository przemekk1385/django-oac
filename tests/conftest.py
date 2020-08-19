import pytest

from django.conf import settings


@pytest.fixture(autouse=True)
def fake_oac_settings():
    if not hasattr(settings, "OAC"):
        setattr(settings, "OAC", {})
    yield
