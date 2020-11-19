from datetime import datetime
from logging import getLogger

import pendulum
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone

UserModel = get_user_model()
logger = getLogger(__package__)


class Token(models.Model):

    access_token = models.TextField()
    refresh_token = models.TextField()
    expires_in = models.PositiveIntegerField(editable=False)
    user = models.ForeignKey(
        UserModel, blank=True, editable=False, null=True, on_delete=models.CASCADE
    )
    issued = models.DateTimeField(editable=False)

    def __str__(self) -> str:
        username = self.user.username if self.user else "unknown"

        return f"issued on {self.issued} for {username}"

    @property
    def has_expired(self) -> bool:
        return timezone.now() >= pendulum.instance(self.issued).add(
            seconds=self.expires_in
        )
