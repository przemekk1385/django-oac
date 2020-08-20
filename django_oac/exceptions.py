class OACError(Exception):

    pass


class BadRequest(OACError):

    pass


class ExpiredState(OACError):

    pass


class FailedRequest(OACError):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class MismatchingState(OACError):

    pass
