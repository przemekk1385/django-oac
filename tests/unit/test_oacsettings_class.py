import pytest

from django_oac.conf import DEFAULTS, OACSettings
from django_oac.exceptions import ConfigurationError


def test_invalid_setting(settings):
    oac_settings = OACSettings(settings, DEFAULTS)

    with pytest.raises(AttributeError):
        assert oac_settings.FOO


def test_missing_setting(settings):
    settings.OAC = {}
    oac_settings = OACSettings(settings, DEFAULTS)

    with pytest.raises(ConfigurationError):
        assert oac_settings.AUTHORIZE_URI
