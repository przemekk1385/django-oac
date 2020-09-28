from typing import Union


def get_missing_keys(required: set, given: Union[list, set, tuple]) -> str:
    return ", ".join(
        reversed(list(map(lambda key: f"'{key}'", required.difference(given))))
    )
