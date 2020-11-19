import pytest

from django_oac.conf import DEFAULTS, OACSettings, import_from_string
from django_oac.exceptions import ConfigurationError


def test_import_from_string_error():
    with pytest.raises(ImportError):
        import_from_string("foo.bar.baz", "FOO")


def test_invalid_setting(settings):
    oac_settings = OACSettings(settings, DEFAULTS)

    with pytest.raises(AttributeError):
        assert oac_settings.FOO


def test_missing_setting(settings):
    settings.OAC = {}
    oac_settings = OACSettings(settings, DEFAULTS)

    with pytest.raises(ConfigurationError):
        assert oac_settings.AUTHORIZE_URI
