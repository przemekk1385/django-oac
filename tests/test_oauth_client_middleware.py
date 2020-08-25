from unittest.mock import patch

from django_oac.apps import DjangoOACConfig
from django_oac.exceptions import ProviderResponseError
from django_oac.middleware import OAuthClientMiddleware

from .helpers import (
    make_mock_related_manager,
    make_mock_request,
    make_mock_token,
    make_mock_user,
)


def test_not_is_authenticated_user(get_response):
    mock_user = make_mock_user(is_authenticated=False)
    mock_request = make_mock_request(user=mock_user,)

    middleware = OAuthClientMiddleware(get_response)
    middleware(mock_request)


def test_user_without_token(get_response):
    mock_user = make_mock_user(token_set=make_mock_related_manager())
    mock_request = make_mock_request(user=mock_user,)

    middleware = OAuthClientMiddleware(get_response)
    middleware(mock_request)


@patch("django_oac.middleware.logout")
def test_token_not_has_expired(get_response):
    mock_token = make_mock_token()
    mock_user = make_mock_user(token_set=make_mock_related_manager(last=mock_token))
    mock_request = make_mock_request(user=mock_user,)

    middleware = OAuthClientMiddleware(get_response)
    middleware(mock_request)


@patch("django_oac.middleware.logout")
def test_token_has_expired(mock_logout, get_response):
    mock_token = make_mock_token(has_expired=True)
    mock_user = make_mock_user(
        email="spam@eggs", token_set=make_mock_related_manager(last=mock_token)
    )
    mock_request = make_mock_request(user=mock_user,)
    mock_logout.return_value = None

    middleware = OAuthClientMiddleware(get_response)
    middleware(mock_request)


@patch("django_oac.middleware.logout")
def test_token_refresh_failed(mock_logout, caplog, get_response):
    mock_token = make_mock_token(
        has_expired=True, refresh=("side_effect", ProviderResponseError("foo"))
    )
    mock_user = make_mock_user(
        email="spam@eggs", token_set=make_mock_related_manager(last=mock_token)
    )
    mock_request = make_mock_request(user=mock_user,)
    mock_logout.return_value = None

    middleware = OAuthClientMiddleware(get_response)
    middleware(mock_request)

    assert "raised ProviderResponseError: foo" == getattr(
        next(
            (
                record
                for record in caplog.records
                if record.name == DjangoOACConfig.name and record.levelname == "ERROR"
            ),
            None,
        ),
        "msg",
        None,
    )
