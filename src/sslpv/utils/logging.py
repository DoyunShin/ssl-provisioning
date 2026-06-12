"""Logging and console output through prompt_toolkit with a plain-text fallback.

All program output (success, status, errors, log records) goes through this module. No
bare ``print()`` is used anywhere in the package. Styled output is attempted first; if the
terminal does not support it (or output is redirected), a plain-text fallback is used.

Never pass secrets (API keys, tokens, nonces, PEM contents) to these functions.
"""

import logging
import sys
from typing import Optional

from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.output.defaults import create_output

INFO_FORMAT = "[%(asctime)s] %(levelname)s # %(message)s"
DEBUG_FORMAT = "[%(asctime)s] [%(filename)s:%(lineno)d] %(levelname)s # %(message)s"

_LEVEL_STYLE = {
    "DEBUG": "fg:ansicyan",
    "INFO": "fg:ansigreen",
    "WARNING": "fg:ansiyellow",
    "ERROR": "fg:ansired",
    "CRITICAL": "fg:ansired bold",
}


def _supports_styling() -> bool:
    """Return True if stdout looks like a styling-capable TTY."""
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def print_message(text: str, style: str = "") -> None:
    """Print a single line through prompt_toolkit with a plain-text fallback.

    Args:
        text(str): The message to print.
        style(str, optional): A prompt_toolkit style string (e.g. ``"fg:ansired"``).
    """
    if _supports_styling() and style:
        try:
            print_formatted_text(FormattedText([(style, text)]))
            return
        except Exception:
            pass
    try:
        print_formatted_text(text)
    except Exception:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()


class PromptToolkitHandler(logging.Handler):
    """Logging handler that emits records through prompt_toolkit.

    Falls back to plain text when styling is unavailable or fails.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
        except Exception:
            self.handleError(record)
            return
        style = _LEVEL_STYLE.get(record.levelname, "") if _supports_styling() else ""
        if style:
            try:
                print_formatted_text(
                    FormattedText([(style, message)]),
                    output=create_output(stderr=True),
                )
                return
            except Exception:
                pass
        try:
            print_formatted_text(message, output=create_output(stderr=True))
        except Exception:
            sys.stderr.write(message + "\n")
            sys.stderr.flush()


def setup_logging(level: int = logging.INFO, name: Optional[str] = None) -> logging.Logger:
    """Configure and return a logger that writes through prompt_toolkit.

    Args:
        level(int): Logging level (e.g. ``logging.INFO`` or ``logging.DEBUG``).
        name(str, optional): Logger name; defaults to the package logger ``sslpv``.

    Return:
        logger(logging.Logger): Configured logger with a single PromptToolkitHandler.
    """
    logger = logging.getLogger(name if name else "sslpv")
    logger.setLevel(level)
    logger.handlers.clear()
    handler = PromptToolkitHandler()
    fmt = DEBUG_FORMAT if level <= logging.DEBUG else INFO_FORMAT
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
    logger.propagate = False
    return logger
