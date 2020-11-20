from abc import ABC, abstractmethod
from logging import getLogger

from django.contrib.auth import get_user_model
from django.utils import timezone

from ..conf import settings as oac_settings
from ..exceptions import NoUserError
from ..models import Token
from ..models_providers.user_provider import UserProviderBase
from ..services import OAuthRequestService, OAuthRequestServiceBase

logger = getLogger(__package__)
UserModel = get_user_model()
UserProvider = oac_settings.USER_PROVIDER_CLASS


class TokenProviderBase(ABC):

    __slots__ = ()

    @abstractmethod
    def create(self, code: str, user_provider: UserProviderBase) -> Token:
        pass

    @abstractmethod
    def refresh(self, instance: Token) -> None:
        pass

    @abstractmethod
    def revoke(self, instance: Token) -> None:
        pass


class DefaultTokenProvider(TokenProviderBase):

    __slots__ = ("_oauth_request_service",)

    def __init__(
        self, oauth_request_service: OAuthRequestServiceBase = OAuthRequestService()
    ):
        self._oauth_request_service = oauth_request_service

    def create(
        self, code: str, user_provider: UserProviderBase = UserProvider()
    ) -> Token:
        data = self._oauth_request_service.get_access_token(code)

        id_token = data.pop("id_token", "")

        user, created = user_provider.get_or_create(id_token)

        if not user:
            raise NoUserError("user provider returned no user")

        if not created and user.token_set.exists():
            user.token_set.all().delete()

        return Token.objects.create(issued=timezone.now(), user=user, **data)

    def refresh(self, instance: Token) -> None:
        data = self._oauth_request_service.refresh_access_token(instance.refresh_token)

        instance.access_token = data.get("access_token", instance.access_token)
        instance.refresh_token = data.get("refresh_token", instance.refresh_token)
        instance.expires_in = data.get("expires_in", instance.expires_in)
        instance.issued = timezone.now()
        instance.save()

    def revoke(self, instance: Token) -> None:
        self._oauth_request_service.revoke_refresh_token(instance.refresh_token)

        instance.delete()
