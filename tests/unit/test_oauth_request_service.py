import pytest
import responses

from django_oac.conf import settings as oac_settings
from django_oac.exceptions import ProviderResponseError
from django_oac.services import OAuthRequestService


@responses.activate
def test_get_access_token_succeeded():
    responses.add(
        responses.POST,
        oac_settings.TOKEN_URI,
        json={
            "access_token": "foo",
            "refresh_token": "bar",
            "expires_in": 3600,
            "id_token": "baz",
        },
        status=200,
    )

    service = OAuthRequestService()
    data = service.get_access_token("spam")

    assert data.get("access_token") == "foo"
    assert data.get("refresh_token") == "bar"
    assert data.get("expires_in") == 3600
    assert data.get("id_token") == "baz"


@pytest.mark.parametrize(
    "status_code,expected_message",
    [
        (400, "provider responded with code 400"),
        (200, "provider response is missing required data"),
    ],
)
@responses.activate
def test_get_access_token_failed(status_code, expected_message):
    responses.add(
        responses.POST, oac_settings.TOKEN_URI, json={"foo": "bar"}, status=status_code,
    )

    service = OAuthRequestService()

    with pytest.raises(ProviderResponseError) as e_info:
        service.get_access_token("spam")

    assert expected_message in str(e_info.value)


@responses.activate
def test_refresh_access_token_succeeded():
    responses.add(
        responses.POST,
        oac_settings.TOKEN_URI,
        json={
            "access_token": "foo",
            "refresh_token": "bar",
            "expires_in": 3600,
            "id_token": "baz",
        },
        status=200,
    )

    service = OAuthRequestService()
    data = service.refresh_access_token("spam")

    assert data.get("access_token") == "foo"
    assert data.get("refresh_token") == "bar"
    assert data.get("expires_in") == 3600
    assert data.get("id_token") == "baz"


@responses.activate
def test_refresh_access_token_failed():
    responses.add(
        responses.POST, oac_settings.TOKEN_URI, json={"foo": "bar"}, status=400,
    )

    service = OAuthRequestService()

    with pytest.raises(ProviderResponseError):
        service.refresh_access_token("spam")


@responses.activate
def test_revoke_refresh_token_failed():
    responses.add(
        responses.POST, oac_settings.REVOKE_URI, json={"foo": "bar"}, status=400,
    )

    service = OAuthRequestService()

    with pytest.raises(ProviderResponseError):
        service.revoke_refresh_token("spam")
