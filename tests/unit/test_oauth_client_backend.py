from uuid import uuid4

import pytest
from django.contrib.auth import get_user_model

from django_oac.backends import OAuthClientBackend

UserModel = get_user_model()


@pytest.mark.django_db
def test_get_user_does_not_exist():
    assert not OAuthClientBackend.get_user(999)


@pytest.mark.django_db
def test_get_user_succeeded():
    user = UserModel.objects.create(
        first_name="spam", last_name="eggs", email="spam@eggs", username=uuid4().hex
    )

    assert OAuthClientBackend.get_user(user.id)
