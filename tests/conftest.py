from unittest.mock import Mock

import pytest


@pytest.fixture
def oac_mock_get_response() -> Mock:
    def make_get_response(*args):
        get_response = Mock()
        get_response.return_value = None
        return get_response

    return make_get_response
