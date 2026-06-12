"""Server infrastructure: rate limiter, spent-nonce tracker, app factory, entrypoint."""

import logging
import os
from collections import OrderedDict
from typing import Callable, Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse

from sslpv.models.config import ServerConfig
from sslpv.response import make_response
from sslpv.services.config import load_server_config
from sslpv.utils.logging import setup_logging

_logger = setup_logging(name="sslpv.server")


class RateLimiter:
    """Per-IP token bucket rate limiter using only the standard library.

    Each IP starts with a full bucket. Tokens refill at ``rate`` per second up
    to ``capacity``. When no tokens remain, ``allow`` returns False.

    Args:
        rate(float): Token refill rate in tokens per second.
        capacity(int): Maximum bucket size (burst ceiling).
        max_ips(int): Maximum number of IPs to track; oldest entry is evicted when
            the limit is exceeded.
    """

    def __init__(
        self,
        rate: float,
        capacity: int,
        max_ips: int = 10000,
        _now: Optional[Callable[[], float]] = None,
    ) -> None:
        self._rate = rate
        self._capacity = capacity
        self._max_ips = max_ips
        self._now: Callable[[], float] = _now if _now is not None else __import__("time").monotonic
        # OrderedDict maps ip -> [tokens, last_refill_time]
        self._buckets: OrderedDict[str, list] = OrderedDict()

    def _refill(self, ip: str, now: float) -> None:
        """Refill the bucket for an IP based on elapsed time.

        Args:
            ip(str): Client IP address.
            now(float): Current monotonic time.
        """
        tokens, last = self._buckets[ip]
        elapsed = now - last
        new_tokens = min(float(self._capacity), tokens + elapsed * self._rate)
        self._buckets[ip] = [new_tokens, now]

    def allow(self, ip: str) -> bool:
        """Check whether a request from ``ip`` is allowed under the rate limit.

        Consumes one token if available. Evicts the oldest tracked IP when
        ``max_ips`` is exceeded.

        Args:
            ip(str): Client IP address.

        Return:
            allowed(bool): True if the request is within the rate limit.
        """
        now = self._now()

        if ip in self._buckets:
            self._buckets.move_to_end(ip)
            self._refill(ip, now)
        else:
            if len(self._buckets) >= self._max_ips:
                self._buckets.popitem(last=False)
            self._buckets[ip] = [float(self._capacity), now]

        tokens, last = self._buckets[ip]
        if tokens >= 1.0:
            self._buckets[ip][0] = tokens - 1.0
            return True
        return False


class SpentNonceSet:
    """One-time-use nonce tracker with expiry.

    Nonces are stored with their expiry timestamp. A nonce is considered absent
    (safe to use) when it has expired. An OrderedDict is used so the oldest entry
    can be efficiently evicted when the set is over capacity.

    Args:
        max_size(int): Maximum number of nonces to track simultaneously.
    """

    def __init__(self, max_size: int = 100000) -> None:
        self._max_size = max_size
        # Maps nonce_b64 -> expiry (Unix int)
        self._store: OrderedDict[str, int] = OrderedDict()

    def add(self, nonce_b64: str, expiry: int) -> None:
        """Record a nonce as spent.

        Evicts the oldest entry when the set is at capacity.

        Args:
            nonce_b64(str): Base64-encoded nonce to mark as spent.
            expiry(int): Unix timestamp after which the nonce can be forgotten.
        """
        if nonce_b64 in self._store:
            self._store.move_to_end(nonce_b64)
            self._store[nonce_b64] = expiry
            return
        if len(self._store) >= self._max_size:
            self._store.popitem(last=False)
        self._store[nonce_b64] = expiry

    def contains(self, nonce_b64: str) -> bool:
        """Return True if the nonce is present and has not yet expired.

        Args:
            nonce_b64(str): Base64-encoded nonce to check.

        Return:
            spent(bool): True if the nonce was spent and has not expired.
        """
        import time

        expiry = self._store.get(nonce_b64)
        if expiry is None:
            return False
        if int(time.time()) > expiry:
            del self._store[nonce_b64]
            return False
        return True

    def purge(self, now: int) -> None:
        """Remove all expired nonces.

        Args:
            now(int): Current Unix timestamp; nonces with expiry <= now are removed.
        """
        expired = [k for k, v in self._store.items() if v <= now]
        for k in expired:
            del self._store[k]


def create_app(config: ServerConfig) -> FastAPI:
    """Create and configure the FastAPI application.

    Sets up application state, registers routers, and installs exception handlers
    that ensure every error response follows the unified envelope.

    Args:
        config(ServerConfig): Validated server configuration.

    Return:
        app(FastAPI): Configured FastAPI application instance.
    """
    # Docs endpoints are disabled; the OpenAPI schema is available only to devs
    # via explicit router-level responses= annotations.
    app = FastAPI(
        title="sslpv",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.state.config = config
    app.state.server_secret = os.urandom(32)
    app.state.spent_nonces = SpentNonceSet()
    # 1 token/second refill, burst of 20 per IP
    app.state.rate_limiter = RateLimiter(rate=1.0, capacity=20)

    # Import here to avoid circular imports at module load time
    from sslpv.routers.certs import router as certs_router

    app.include_router(certs_router)

    @app.exception_handler(HTTPException)
    async def handle_http_error(request: Request, exc: HTTPException) -> JSONResponse:
        return make_response(exc.status_code, exc.detail)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return make_response(422, "validation error", exc.errors())

    @app.exception_handler(Exception)
    async def handle_generic_error(request: Request, exc: Exception) -> JSONResponse:
        _logger.error("unhandled exception: %s", type(exc).__name__)
        return make_response(500, "internal server error")

    return app


def run_server(config_path: str) -> None:
    """Load config and start the uvicorn server with TLS.

    TLS is handled by uvicorn using ssl.PROTOCOL_TLS_SERVER, which negotiates
    TLS 1.2 or higher. A modern cipher suite is requested.

    Args:
        config_path(str): Filesystem path to the JSON server config file.
    """
    config = load_server_config(config_path)
    app = create_app(config)

    _logger.info("starting sslpv server on %s:%d", config.host, config.port)

    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        ssl_certfile=config.tls_certfile,
        ssl_keyfile=config.tls_keyfile,
        # Modern cipher suite; uvicorn uses ssl.PROTOCOL_TLS_SERVER (TLS 1.2+)
        ssl_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5",
        workers=1,
        log_level="warning",
    )
