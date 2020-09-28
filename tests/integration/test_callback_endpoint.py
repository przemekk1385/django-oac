import json
from unittest.mock import Mock, PropertyMock, patch

import pytest
from django.shortcuts import reverse
from django.utils import timezone

from ..common import ID_TOKEN_PAYLOAD, USER_PAYLOAD


@pytest.mark.django_db
@patch("django_oac.stores.requests")
@patch("django_oac.models.requests")
def test_callback_endpoint(mock_models_requests, mock_stores_requests, client, oac_jwt):
    session = client.session
    session["OAC_STATE_STR"] = "test"
    session["OAC_STATE_TIMESTAMP"] = timezone.now().timestamp() - 240
    session["OAC_CLIENT_IP"] = "127.0.0.1"
    session.save()

    oac_jwt.kid = "foo"
    oac_jwt.id_token = ID_TOKEN_PAYLOAD

    mock_post_response = Mock()
    type(mock_post_response).status_code = PropertyMock(return_value=200)
    mock_post_response.json.return_value = {
        "access_token": "foo",
        "refresh_token": "bar",
        "expires_in": 3600,
        "id_token": oac_jwt.id_token,
    }

    mock_get_response = Mock()
    type(mock_get_response).status_code = PropertyMock(return_value=200)
    type(mock_get_response).content = PropertyMock(return_value=oac_jwt.jwk_set)

    mock_models_requests.post.return_value = mock_post_response
    mock_stores_requests.get.return_value = mock_get_response

    response = client.get(
        reverse("django_oac:callback"), {"state": "test", "code": "foo"}, follow=True,
    )

    assert response.status_code == 200
    assert json.loads(response.content) == USER_PAYLOAD
