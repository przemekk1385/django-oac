import logging
from unittest.mock import Mock, PropertyMock, patch

from django.contrib.auth.models import AnonymousUser

from django_oac.apps import DjangoOACConfig
from django_oac.exceptions import ProviderResponseError
from django_oac.middleware import OAuthClientMiddleware


def test_not_is_authenticated_user(rf, caplog, oac_mock_get_response):
    request = rf.get("foo")
    request.session = {
        "OAC_CLIENT_IP": "127.0.0.1",
        "OAC_STATE_STR": "test",
    }
    request.user = AnonymousUser()

    caplog.set_level(logging.INFO, logger=DjangoOACConfig.name)
    middleware = OAuthClientMiddleware(oac_mock_get_response)

    middleware(request)

    assert not caplog.records


def test_user_without_token(rf, caplog, oac_mock_get_response):
    user = Mock()
    user.token_set.last.return_value = None

    request = rf.get("foo")
    request.session = {
        "OAC_CLIENT_IP": "127.0.0.1",
        "OAC_STATE_STR": "test",
    }
    request.user = user

    caplog.set_level(logging.INFO, logger=DjangoOACConfig.name)
    middleware = OAuthClientMiddleware(oac_mock_get_response)

    middleware(request)

    assert caplog.records[0].msg.startswith("no access token found")


def test_token_not_has_expired(rf, caplog, oac_mock_get_response):
    token = Mock()
    type(token).has_expired = PropertyMock(return_value=False)
    user = Mock()
    type(user).email = "spam@eggs"
    user.token_set.last.return_value = token

    request = rf.get("foo")
    request.session = {
        "OAC_CLIENT_IP": "127.0.0.1",
        "OAC_STATE_STR": "test",
    }
    request.user = user

    caplog.set_level(logging.DEBUG, logger=DjangoOACConfig.name)
    middleware = OAuthClientMiddleware(oac_mock_get_response)

    middleware(request)

    assert caplog.records[0].msg.endswith("is valid")


@patch("django_oac.middleware.logout")
def test_token_has_expired(mock_logout, rf, caplog, oac_mock_get_response):
    token = Mock()
    type(token).has_expired = PropertyMock(return_value=True)
    user = Mock()
    type(user).email = "spam@eggs"
    user.token_set.last.return_value = token

    mock_logout.return_value = None

    request = rf.get("foo")
    request.session = {
        "OAC_CLIENT_IP": "127.0.0.1",
        "OAC_STATE_STR": "test",
    }
    request.user = user

    caplog.set_level(logging.INFO, logger=DjangoOACConfig.name)
    middleware = OAuthClientMiddleware(oac_mock_get_response)

    middleware(request)

    assert caplog.records[0].msg.endswith("has expired")
    assert caplog.records[1].msg.endswith("has been refreshed")


@patch("django_oac.middleware.logout")
def test_token_refresh_failed(mock_logout, rf, caplog, oac_mock_get_response):
    token = Mock()
    type(token).has_expired = PropertyMock(return_value=True)
    token.refresh.side_effect = ProviderResponseError("foo")
    user = Mock()
    type(user).email = "spam@eggs"
    user.token_set.last.return_value = token

    mock_logout.return_value = None

    request = rf.get("foo")
    request.session = {
        "OAC_CLIENT_IP": "127.0.0.1",
        "OAC_STATE_STR": "test",
    }
    request.user = user

    caplog.set_level(logging.ERROR, logger=DjangoOACConfig.name)
    middleware = OAuthClientMiddleware(oac_mock_get_response)

    middleware(request)

    assert caplog.records[0].msg.startswith("raised ProviderResponseError")
