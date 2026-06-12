"""Standard API response envelope and helper.

Every endpoint returns the unified ``{"status", "message", "data"}`` envelope through
:func:`make_response`. No endpoint returns a raw value or a bare model.
"""

from typing import Any, Optional

from fastapi.responses import JSONResponse
from pydantic import BaseModel


class APIResponse(BaseModel):
    """Standard API response envelope.

    Args:
        status(int): HTTP status code.
        message(str): Human-readable message.
        data(Any): Response payload (dict, list, or None).
    """

    status: int
    message: str
    data: Optional[Any] = None


def make_response(status: int, message: str, data: Any = None) -> JSONResponse:
    """Build a standard JSON response.

    Args:
        status(int): HTTP status code.
        message(str): Human-readable message.
        data(Any, optional): Response payload.

    Return:
        response(JSONResponse): FastAPI JSONResponse with the unified format.
    """
    return JSONResponse(
        status_code=status,
        content={"status": status, "message": message, "data": data},
    )
