"""Server configuration loading and validation."""

import json
import os

from sslpv.models.config import ServerConfig
from sslpv.utils.logging import setup_logging

_logger = setup_logging(name="sslpv.config")


def read_pem_file(path: str) -> bytes:
    """Read a PEM file as raw bytes.

    Args:
        path(str): Filesystem path to the PEM file.

    Return:
        data(bytes): Raw file contents.

    Raises:
        ValueError: If the file cannot be read.
    """
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise ValueError(f"cannot read file '{path}': {exc}") from exc


def _check_file_readable(path: str, label: str) -> None:
    """Verify a path exists and is readable.

    Args:
        path(str): Filesystem path to check.
        label(str): Human-readable label for error messages.

    Raises:
        ValueError: If the file does not exist or is not readable.
    """
    if not os.path.isfile(path):
        raise ValueError(f"{label} file not found: '{path}'")
    if not os.access(path, os.R_OK):
        raise ValueError(f"{label} file is not readable: '{path}'")


def _check_config_permissions(path: str) -> None:
    """Verify the config file is not readable by group or other.

    Args:
        path(str): Filesystem path to the config file.

    Raises:
        ValueError: If the file has group or other read/write/execute bits set.
    """
    mode = os.stat(path).st_mode
    if mode & 0o077 != 0:
        raise ValueError(
            f"config file must not be readable by group/other (chmod 600): '{path}'"
        )


def _warn_insecure_key_permissions(path: str) -> None:
    """Emit a warning if the private key file is readable by group or other.

    Args:
        path(str): Filesystem path to the private key file.
    """
    mode = os.stat(path).st_mode
    if mode & 0o077 != 0:
        _logger.warning(
            "private key file '%s' is readable by group/other and should be chmod 600",
            path,
        )


def _validate_apikeys(apikeys: list[str]) -> None:
    """Validate that apikeys is non-empty and contains no blank entries.

    Args:
        apikeys(list[str]): List of API keys to validate.

    Raises:
        ValueError: If the list is empty or contains a whitespace-only key.
    """
    if not apikeys:
        raise ValueError("apikeys must not be empty")
    for key in apikeys:
        if not key or not key.strip():
            raise ValueError("apikeys must not contain empty or whitespace-only entries")


def load_server_config(path: str) -> ServerConfig:
    """Load and validate a ServerConfig from a JSON file.

    Validates:
    - Config file permissions (must be 0600 or stricter).
    - Referenced PEM files exist and are readable.
    - apikeys is non-empty and contains no blank entries.

    Args:
        path(str): Filesystem path to the JSON config file.

    Return:
        config(ServerConfig): Validated server configuration.

    Raises:
        ValueError: On any validation failure.
    """
    _check_config_permissions(path)

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except OSError as exc:
        raise ValueError(f"cannot read config file '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"config file is not valid JSON: {exc}") from exc

    config = ServerConfig(**raw)

    _validate_apikeys(config.apikeys)

    _check_file_readable(config.fullchain, "fullchain")
    _check_file_readable(config.privkey, "privkey")

    if config.server_certfile is not None:
        _check_file_readable(config.server_certfile, "server_certfile")
    if config.server_keyfile is not None:
        _check_file_readable(config.server_keyfile, "server_keyfile")

    _warn_insecure_key_permissions(config.privkey)
    if config.server_keyfile is not None:
        _warn_insecure_key_permissions(config.server_keyfile)

    return config
