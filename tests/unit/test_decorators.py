from logging import Logger
from unittest.mock import Mock

import pytest
from django.http import HttpRequest, HttpResponse
from django.utils import timezone

from django_oac.decorators import (
    validate_query_string,
    validate_state_expiration,
    validate_state_matching,
)


@pytest.mark.parametrize(
    "query_dict,expected_status_code",
    [
        ({"code": "foo"}, 400),
        ({"state": "foo"}, 400),
        ({"code": "foo", "state": "bar"}, 200),
    ],
)
def test_validate_query_string(query_dict, expected_status_code, rf):
    @validate_query_string
    def test_func(_: HttpRequest, __: Logger = None) -> HttpResponse:
        return HttpResponse("foo")

    request = rf.get("foo", query_dict)

    response = test_func(request, Mock())

    assert response.status_code == expected_status_code


@pytest.mark.parametrize(
    "seconds,expected_status_code",
    [(301, 400), (299, 200)],
)
def test_validate_state_expiration(seconds, expected_status_code, rf):
    @validate_state_expiration
    def test_func(_: HttpRequest, __: Logger = None) -> HttpResponse:
        return HttpResponse("foo")

    request = rf.get("foo")
    request.session = {
        "OAC_STATE_TIMESTAMP": timezone.now().timestamp() - seconds,
    }

    response = test_func(request, Mock())

    assert response.status_code == expected_status_code


@pytest.mark.parametrize(
    "query_dict,oac_state_str,expected_status_code",
    [({"state": "foo"}, "bar", 400), ({"state": "foo"}, "foo", 200)],
)
def test_validate_state_matching(query_dict, oac_state_str, expected_status_code, rf):
    @validate_state_matching
    def test_func(_: HttpRequest, __: Logger = None) -> HttpResponse:
        return HttpResponse("foo")

    request = rf.get("foo", query_dict)
    request.session = {
        "OAC_STATE_STR": oac_state_str,
    }

    response = test_func(request, Mock())

    assert response.status_code == expected_status_code
