from typing import Union
from unittest.mock import MagicMock, PropertyMock


def make_mock_response(
    status_code: int, json_dict: Union[dict, None] = None
) -> MagicMock:
    json_dict = json_dict or {}
    mock_response = MagicMock()
    mock_response.json.return_value = json_dict
    type(mock_response).status_code = PropertyMock(return_value=status_code)
    return mock_response
