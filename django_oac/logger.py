from logging import Formatter, getLogger
from logging.handlers import RotatingFileHandler
from pathlib import Path


def get_extra(scope: str, client_ip: str = "n/a", state_str: str = "n/a") -> dict:
    return {
        "scope": scope,
        "ip_state": f"{client_ip}:{state_str}",
    }


def set_logger(log_dir: Path):
    if not log_dir.is_dir():
        log_dir.mkdir(parents=True)

    logger = getLogger(__package__)

    file_handler = RotatingFileHandler(
        (log_dir / f"{__package__}.log").as_posix(), maxBytes=(5 * 1024 ** 2),
    )
    file_handler.setFormatter(
        Formatter(
            "%(asctime)s"
            " - %(scope)s"
            " - %(ip_state)s"
            " - %(levelname)s"
            " - %(message)s"
        )
    )
    logger.addHandler(file_handler)
    logger.setLevel("INFO")
