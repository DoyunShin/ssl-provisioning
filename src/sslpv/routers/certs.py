"""Certificate and private-key provisioning endpoints."""

import base64
import os
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from sslpv.dependencies import TTL, verify_auth
from sslpv.response import make_response
from sslpv.services.config import read_pem_file
from sslpv.utils.crypto import (
    derive_shared_key,
    encrypt_payload,
    generate_ephemeral_keypair,
    sign_challenge,
)
from sslpv.utils.logging import setup_logging

_logger = setup_logging(name="sslpv.routers.certs")

router = APIRouter(tags=["certs"])

_CHALLENGE_RESPONSES: dict[int, Any] = {
    200: {
        "description": "Challenge issued",
        "content": {
            "application/json": {
                "examples": {
                    "success": {
                        "summary": "Challenge successfully issued",
                        "value": {
                            "status": 200,
                            "message": "challenge issued",
                            "data": {
                                "nonce": "dGhpcyBpcyBhIHRlc3Qgbm9uY2UhISEhISEh",
                                "issue_ts": 1718000000,
                                "sig": "abc123base64sighere==",
                                "ttl": 60,
                            },
                        },
                    }
                }
            }
        },
    },
    429: {
        "description": "Rate limited",
        "content": {
            "application/json": {
                "examples": {
                    "rate_limited": {
                        "summary": "Too many requests from this IP",
                        "value": {
                            "status": 429,
                            "message": "rate limited",
                            "data": None,
                        },
                    }
                }
            }
        },
    },
}

_CERT_RESPONSES: dict[int, Any] = {
    200: {
        "description": "Encrypted certificate payload",
        "content": {
            "application/json": {
                "examples": {
                    "success": {
                        "summary": "Certificate returned encrypted",
                        "value": {
                            "status": 200,
                            "message": "certificate retrieved",
                            "data": {
                                "server_pubkey": "srvpubkeybase64==",
                                "nonce": "nonce12bytesb64==",
                                "ciphertext": "encryptedcertbase64==",
                            },
                        },
                    }
                }
            }
        },
    },
    400: {
        "description": "Invalid or missing X-Client-Pubkey header",
        "content": {
            "application/json": {
                "examples": {
                    "bad_pubkey": {
                        "summary": "X-Client-Pubkey header is invalid",
                        "value": {
                            "status": 400,
                            "message": "invalid X-Client-Pubkey header",
                            "data": None,
                        },
                    }
                }
            }
        },
    },
    401: {
        "description": "Authentication failure",
        "content": {
            "application/json": {
                "examples": {
                    "unauthorized": {
                        "summary": "Token missing, expired, or invalid",
                        "value": {
                            "status": 401,
                            "message": "unauthorized",
                            "data": None,
                        },
                    }
                }
            }
        },
    },
    429: {
        "description": "Rate limited",
        "content": {
            "application/json": {
                "examples": {
                    "rate_limited": {
                        "summary": "Too many requests from this IP",
                        "value": {
                            "status": 429,
                            "message": "rate limited",
                            "data": None,
                        },
                    }
                }
            }
        },
    },
    500: {
        "description": "Certificate file unavailable",
        "content": {
            "application/json": {
                "examples": {
                    "unavailable": {
                        "summary": "Server could not read the certificate file",
                        "value": {
                            "status": 500,
                            "message": "certificate unavailable",
                            "data": None,
                        },
                    }
                }
            }
        },
    },
}

_PRIVKEY_RESPONSES: dict[int, Any] = {
    200: {
        "description": "Encrypted private key payload",
        "content": {
            "application/json": {
                "examples": {
                    "success": {
                        "summary": "Private key returned encrypted",
                        "value": {
                            "status": 200,
                            "message": "private key retrieved",
                            "data": {
                                "server_pubkey": "srvpubkeybase64==",
                                "nonce": "nonce12bytesb64==",
                                "ciphertext": "encryptedkeybase64==",
                            },
                        },
                    }
                }
            }
        },
    },
    400: _CERT_RESPONSES[400],
    401: _CERT_RESPONSES[401],
    429: _CERT_RESPONSES[429],
    500: {
        "description": "Private key file unavailable",
        "content": {
            "application/json": {
                "examples": {
                    "unavailable": {
                        "summary": "Server could not read the private key file",
                        "value": {
                            "status": 500,
                            "message": "certificate unavailable",
                            "data": None,
                        },
                    }
                }
            }
        },
    },
}


def _encrypt_pem_for_client(pem_bytes: bytes, client_pubkey: bytes, apikey: str) -> dict:
    """Encrypt PEM bytes for the client using ephemeral ECDH + AES-256-GCM.

    Args:
        pem_bytes(bytes): PEM content to encrypt.
        client_pubkey(bytes): 32-byte raw X25519 public key of the client.
        apikey(str): Matched API key used to bind the HKDF derivation.

    Return:
        payload(dict): Dict with keys ``server_pubkey``, ``nonce``, ``ciphertext``
            (all base64-encoded strings).
    """
    server_priv, server_pub_raw = generate_ephemeral_keypair()
    key = derive_shared_key(server_priv, client_pubkey, apikey)
    nonce, ciphertext = encrypt_payload(key, pem_bytes)
    return {
        "server_pubkey": base64.b64encode(server_pub_raw).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


@router.get("/challenge", responses=_CHALLENGE_RESPONSES)
async def get_challenge(request: Request) -> JSONResponse:
    """Issue a signed challenge nonce for the client to include in its auth token.

    Rate-limited per client IP.

    Return:
        response(JSONResponse): 200 with ``{nonce, issue_ts, sig, ttl}``; 429 if limited.
    """
    config = request.app.state.config
    server_secret: bytes = request.app.state.server_secret
    rate_limiter = request.app.state.rate_limiter

    ip = request.client.host if request.client else "unknown"
    if ip in config.trusted_proxies:
        forwarded = request.headers.get("X-Forwarded-For", "")
        first = forwarded.split(",")[0].strip()
        if first:
            ip = first

    if not rate_limiter.allow(ip):
        raise HTTPException(429, "rate limited")

    nonce = os.urandom(32)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    issue_ts = int(time.time())
    sig = sign_challenge(server_secret, nonce_b64, issue_ts)

    return make_response(
        200,
        "challenge issued",
        {"nonce": nonce_b64, "issue_ts": issue_ts, "sig": sig, "ttl": TTL},
    )


@router.get("/cert", responses=_CERT_RESPONSES)
async def get_cert(
    request: Request, auth: dict = Depends(verify_auth)
) -> JSONResponse:
    """Return the fullchain certificate, encrypted for the authenticated client.

    The PEM bytes are read fresh from disk on each request.

    Return:
        response(JSONResponse): 200 with encrypted payload; 401/429/500 on failure.
    """
    config = request.app.state.config

    try:
        pem_bytes = read_pem_file(config.fullchain)
    except ValueError:
        _logger.error("failed to read certificate file")
        return make_response(500, "certificate unavailable")

    payload = _encrypt_pem_for_client(pem_bytes, auth["client_pubkey"], auth["apikey"])
    return make_response(200, "certificate retrieved", payload)


@router.get("/privkey", responses=_PRIVKEY_RESPONSES)
async def get_privkey(
    request: Request, auth: dict = Depends(verify_auth)
) -> JSONResponse:
    """Return the private key, encrypted for the authenticated client.

    The PEM bytes are read fresh from disk on each request.

    Return:
        response(JSONResponse): 200 with encrypted payload; 401/429/500 on failure.
    """
    config = request.app.state.config

    try:
        pem_bytes = read_pem_file(config.privkey)
    except ValueError:
        _logger.error("failed to read private key file")
        return make_response(500, "certificate unavailable")

    payload = _encrypt_pem_for_client(pem_bytes, auth["client_pubkey"], auth["apikey"])
    return make_response(200, "private key retrieved", payload)
