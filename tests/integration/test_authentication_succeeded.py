import json
from unittest.mock import Mock, PropertyMock, patch
from urllib.parse import parse_qsl, urlparse

import pytest
from django.shortcuts import reverse


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_authentication_succeeded(mock_requests, settings, client, oac_jwk):
    settings.OAC = {
        "authorize_uri": "http://www.example.com/",
        "token_uri": "http://www.example.com/",
        "revoke_uri": "http://www.example.com/",
        "jwks_uri": "http://www.example.com/",
        "client_id": "foo-bar-baz",
    }

    response = client.get(reverse("django_oac:authenticate"))

    assert 302 == response.status_code

    query_dict = dict(parse_qsl(urlparse(response.url).query))

    oac_jwk.kid = "foo"
    oac_jwk.id_token = {
        "aud": "foo-bar-baz",
        "first_name": "spam",
        "last_name": "eggs",
        "email": "spam@eggs",
        "username": "spam.eggs",
    }

    mock_post_response = Mock()
    type(mock_post_response).status_code = PropertyMock(return_value=200)
    mock_post_response.json.return_value = {
        "access_token": "foo",
        "refresh_token": "bar",
        "expires_in": 3600,
        "id_token": oac_jwk.id_token,
    }

    mock_get_response = Mock()
    type(mock_get_response).status_code = PropertyMock(return_value=200)
    mock_get_response.json.return_value = {
        "keys": [oac_jwk.jwk],
    }

    mock_requests.post.return_value = mock_post_response
    mock_requests.get.return_value = mock_get_response

    response = client.get(
        reverse("django_oac:callback"),
        {"state": query_dict["state"], "code": "foo"},
        follow=True,
    )

    assert 200 == response.status_code
    assert {
        "first_name": "spam",
        "last_name": "eggs",
        "email": "spam@eggs",
        "username": "spam.eggs",
    } == json.loads(response.content)

    response = client.get(reverse("django_oac:logout"), follow=True)

    assert 200 == response.status_code
    assert {
        "first_name": "",
        "last_name": "",
        "email": "",
        "username": "",
    } == json.loads(response.content)
