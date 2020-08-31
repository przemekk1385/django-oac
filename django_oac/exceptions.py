class OACError(Exception):

    pass


class ExpiredStateError(OACError):

    pass


class InsufficientPayloadError(OACError):

    pass


class MismatchingStateError(OACError):

    pass


class ProviderRequestError(OACError):

    pass


class ProviderResponseError(OACError):

    pass
