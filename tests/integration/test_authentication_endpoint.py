import pytest
from django.shortcuts import reverse


@pytest.mark.django_db
def test_authentication_endpoint(settings, client, oac_jwk):
    settings.OAC = {
        "authorize_uri": "http://www.example.com/",
        "token_uri": "http://www.example.com/",
        "revoke_uri": "http://www.example.com/",
        "jwks_uri": "http://www.example.com/",
        "client_id": "foo-bar-baz",
    }

    response = client.get(reverse("django_oac:authenticate"))

    assert 302 == response.status_code
