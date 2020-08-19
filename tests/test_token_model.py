import pytest
import pendulum

from django.utils import timezone

from django_oac.models import Token


@pytest.mark.django_db
def test_has_expired_property():
    payload = {
        "access_token": "foo",
        "refresh_token": "bar",
        "expires_in": 3600,
        "issued": pendulum.instance(timezone.now()).subtract(seconds=3601),
    }

    token = Token.objects.create(**payload)

    assert token.has_expired
