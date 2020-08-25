from typing import Union
from unittest.mock import MagicMock, PropertyMock
from uuid import uuid4


def make_mock_request(
    absolute_uri: str = None, session_dict: dict = None, user: MagicMock = None
):
    session_dict = {
        **{"OAC_CLIENT_IP": "127.0.0.1", "OAC_STATE_STR": "test"},
        **(session_dict or {}),
    }
    mock_request = MagicMock()
    mock_request.build_absolute_uri.return_value = absolute_uri
    type(mock_request).session = PropertyMock(return_value=session_dict)
    type(mock_request).user = PropertyMock(return_value=user)
    return mock_request


def make_mock_response(
    status_code: int, json_dict: Union[dict, None] = None
) -> MagicMock:
    json_dict = json_dict or {}
    mock_response = MagicMock()
    mock_response.json.return_value = json_dict
    type(mock_response).status_code = PropertyMock(return_value=status_code)
    return mock_response


def make_mock_related_manager(
    first: MagicMock = None, last: MagicMock = None,
) -> MagicMock:
    related_manager = MagicMock()
    related_manager.first.return_value = first
    related_manager.last.return_value = last
    return related_manager


def make_mock_token(
    has_expired: bool = False,
    delete: tuple = ("return_value", None),
    refresh: tuple = ("return_value", None),
    revoke: tuple = ("return_value", None),
) -> MagicMock:
    mock_token = MagicMock()
    setattr(mock_token.delete, *delete)
    setattr(mock_token.refresh, *refresh)
    setattr(mock_token.revoke, *revoke)
    type(mock_token).has_expired = PropertyMock(return_value=has_expired)
    return mock_token


def make_mock_user(
    email: str = None, is_authenticated: bool = True, token_set: MagicMock = None,
) -> MagicMock:
    mock_user = MagicMock()
    type(mock_user).email = PropertyMock(return_value=email)
    type(mock_user).is_authenticated = PropertyMock(return_value=is_authenticated)
    type(mock_user).token_set = PropertyMock(return_value=token_set)
    type(mock_user).username = PropertyMock(return_value=uuid4().hex)
    return mock_user
