from unittest.mock import MagicMock

import pytest


@pytest.fixture
def get_response() -> MagicMock:
    def make_get_response(*args):
        get_response = MagicMock()
        get_response.return_value = None
        return get_response

    return make_get_response
