"""FastAPI dependencies: authentication and rate limiting."""

import base64
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric import x25519
from fastapi import Depends, HTTPException, Request

from sslpv.utils.crypto import verify_challenge, verify_proof

# Challenge TTL in seconds
TTL = 60

# Maximum allowed clock skew between client and server
_CLOCK_SKEW = 5


def _parse_auth_header(authorization: str) -> tuple[str, int, str, str]:
    """Parse a Bearer token of the form ``Bearer v1.<nonce>.<ts>.<sig>.<proof>``.

    Args:
        authorization(str): Raw Authorization header value.

    Return:
        parts(tuple): ``(nonce_b64, issue_ts, sig_b64, proof_b64)``.

    Raises:
        HTTPException: 401 if the header is missing, malformed, or wrong version.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "unauthorized")

    token = authorization[len("Bearer "):]

    if not token.startswith("v1."):
        raise HTTPException(401, "unauthorized")

    body = token[len("v1."):]
    # nonce_b64, issue_ts, sig_b64, proof_b64 — base64 segments never contain '.'
    parts = body.split(".")
    if len(parts) != 4:
        raise HTTPException(401, "unauthorized")

    nonce_b64, ts_str, sig_b64, proof_b64 = parts

    try:
        issue_ts = int(ts_str)
    except ValueError:
        raise HTTPException(401, "unauthorized")

    return nonce_b64, issue_ts, sig_b64, proof_b64


def _parse_client_pubkey(header_value: str) -> tuple[bytes, str]:
    """Decode and validate the X-Client-Pubkey header.

    Args:
        header_value(str): Base64-encoded 32-byte X25519 public key.

    Return:
        result(tuple): ``(raw_bytes, b64_string)``.

    Raises:
        HTTPException: 400 if the header is missing, not valid base64, or not 32 bytes.
    """
    try:
        raw = base64.b64decode(header_value, validate=True)
    except Exception:
        raise HTTPException(400, "invalid X-Client-Pubkey header")

    if len(raw) != 32:
        raise HTTPException(400, "invalid X-Client-Pubkey header")

    try:
        x25519.X25519PublicKey.from_public_bytes(raw)
    except Exception:
        raise HTTPException(400, "invalid X-Client-Pubkey header")

    return raw, header_value


def _get_client_ip(request: Request, trusted_proxies: list[str]) -> str:
    """Determine the real client IP, honouring trusted proxy forwarding.

    Args:
        request(Request): The incoming FastAPI request.
        trusted_proxies(list[str]): IP addresses of trusted reverse proxies.

    Return:
        ip(str): The effective client IP address.
    """
    direct_ip = request.client.host if request.client else "unknown"
    if direct_ip in trusted_proxies:
        forwarded = request.headers.get("X-Forwarded-For", "")
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return direct_ip


async def verify_auth(request: Request) -> dict[str, Any]:
    """FastAPI dependency that authenticates and rate-limits every protected request.

    Authentication steps (order is security-critical):
    1. Determine real client IP; apply rate limiting.
    2. Parse Authorization header (Bearer v1 token) and X-Client-Pubkey header.
    3. Verify challenge signature.
    4. Verify token freshness (TTL and clock skew).
    5. Check nonce has not been spent.
    6. Verify API-key proof (bound to method, path, nonce, pubkey).
    7. Mark nonce as spent; return auth context.

    All 401 failures return the same message ("unauthorized") to avoid oracles.

    Args:
        request(Request): The incoming FastAPI request.

    Return:
        auth(dict): ``{"apikey": str, "client_pubkey": bytes}``.

    Raises:
        HTTPException: 401 for auth failures, 429 for rate limiting, 400 for bad headers.
    """
    config = request.app.state.config
    server_secret: bytes = request.app.state.server_secret
    spent_nonces = request.app.state.spent_nonces
    rate_limiter = request.app.state.rate_limiter

    # Step a: rate limiting
    ip = _get_client_ip(request, config.trusted_proxies)
    if not rate_limiter.allow(ip):
        raise HTTPException(429, "rate limited")

    # Step b: parse Authorization header
    authorization = request.headers.get("Authorization", "")
    nonce_b64, issue_ts, sig_b64, proof_b64 = _parse_auth_header(authorization)

    client_pubkey_header = request.headers.get("X-Client-Pubkey", "")
    if not client_pubkey_header:
        raise HTTPException(400, "invalid X-Client-Pubkey header")
    client_pubkey_raw, client_pubkey_b64 = _parse_client_pubkey(client_pubkey_header)

    # Step c: verify challenge signature
    if not verify_challenge(server_secret, nonce_b64, issue_ts, sig_b64):
        raise HTTPException(401, "unauthorized")

    # Step d: check expiry and clock skew
    now = int(time.time())
    if now - issue_ts > TTL:
        raise HTTPException(401, "unauthorized")
    if issue_ts > now + _CLOCK_SKEW:
        raise HTTPException(401, "unauthorized")

    # Step e: check spent nonce
    if spent_nonces.contains(nonce_b64):
        raise HTTPException(401, "unauthorized")

    # Step f: verify proof (bound to method, path, nonce, pubkey, apikey)
    matched_apikey = verify_proof(
        proof_b64,
        config.apikeys,
        request.method,
        request.url.path,
        nonce_b64,
        issue_ts,
        client_pubkey_b64,
    )
    if matched_apikey is None:
        # Do NOT mark the nonce as spent — the attacker has not authenticated
        raise HTTPException(401, "unauthorized")

    # Step g: mark nonce spent and return auth context
    spent_nonces.add(nonce_b64, expiry=issue_ts + TTL)

    return {"apikey": matched_apikey, "client_pubkey": client_pubkey_raw}
