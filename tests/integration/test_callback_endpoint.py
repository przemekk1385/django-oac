import json
from unittest.mock import Mock, PropertyMock, patch
from uuid import uuid4

import pytest
from django.shortcuts import reverse
from django.utils import timezone


@pytest.mark.django_db
@patch("django_oac.models.requests")
def test_callback_endpoint(mock_requests, settings, client, oac_jwk):
    state_str = uuid4().hex

    settings.OAC = {
        "authorize_uri": "http://www.example.com/",
        "token_uri": "http://www.example.com/",
        "revoke_uri": "http://www.example.com/",
        "jwks_uri": "http://www.example.com/",
        "client_id": "foo-bar-baz",
    }

    session = client.session
    session["OAC_STATE_STR"] = state_str
    session["OAC_STATE_TIMESTAMP"] = timezone.now().timestamp() - 240
    session["OAC_CLIENT_IP"] = "127.0.0.1"
    session.save()

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
    type(mock_get_response).content = PropertyMock(
        return_value=json.dumps({"keys": [oac_jwk.jwk]})
    )

    mock_requests.post.return_value = mock_post_response
    mock_requests.get.return_value = mock_get_response

    response = client.get(
        reverse("django_oac:callback"),
        {"state": state_str, "code": "foo"},
        follow=True,
    )

    assert 200 == response.status_code
    assert {
        "first_name": "spam",
        "last_name": "eggs",
        "email": "spam@eggs",
        "username": "spam.eggs",
    } == json.loads(response.content)
