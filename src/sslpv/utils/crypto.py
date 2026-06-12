"""Pure cryptographic helpers shared by the server and client.

Covers three concerns, all stateless and side-effect free:

1. End-to-end payload encryption: ephemeral X25519 ECDH + HKDF-SHA256 (bound to the API
   key) -> AES-256-GCM. Only a party holding the API key can derive the session key, so
   the scheme provides both confidentiality and application-layer server authenticity.
2. Stateless signed challenge: the server signs ``(nonce, issue_ts)`` with a per-startup
   secret so it can later verify a challenge it issued without storing anything.
3. API-key proof: the client proves knowledge of the API key by HMAC over a canonical
   message that binds the challenge, HTTP method, endpoint path, and its ephemeral public
   key, so a proof cannot be replayed against a different endpoint.

The canonical byte-for-byte messages are defined here and MUST be identical on both sides.
"""

import base64
import hmac
from hashlib import sha256
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509 import load_pem_x509_certificate

HKDF_INFO_PREFIX = b"sslpv-v1"
CHALLENGE_PREFIX = "sslpv-chal-v1"
PROOF_PREFIX = "sslpv-v1"
GCM_NONCE_SIZE = 12


def _b64e(raw: bytes) -> str:
    """Encode bytes as standard base64 text."""
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    """Decode standard base64 text to bytes (raises ValueError on bad input)."""
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64 input") from exc


def generate_ephemeral_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
    """Generate an ephemeral X25519 keypair.

    Return:
        keypair(tuple): ``(private_key, public_raw)`` where ``public_raw`` is the 32-byte
            raw public key.
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_raw


def derive_shared_key(
    private_key: x25519.X25519PrivateKey, peer_public: bytes, apikey: str
) -> bytes:
    """Derive a 32-byte AES-256-GCM key from an X25519 exchange bound to the API key.

    Args:
        private_key(X25519PrivateKey): This party's ephemeral private key.
        peer_public(bytes): The peer's 32-byte raw X25519 public key.
        apikey(str): The shared API key; bound into the HKDF ``info`` so only holders of
            the key derive the same session key.

    Return:
        key(bytes): A 32-byte symmetric key.
    """
    peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public)
    shared = private_key.exchange(peer_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO_PREFIX + apikey.encode("utf-8"),
    ).derive(shared)


def encrypt_payload(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """Encrypt a payload with AES-256-GCM under a random nonce.

    Args:
        key(bytes): 32-byte symmetric key.
        plaintext(bytes): Data to encrypt.

    Return:
        result(tuple): ``(nonce, ciphertext)`` where ``ciphertext`` includes the GCM tag.
    """
    import os

    nonce = os.urandom(GCM_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt an AES-256-GCM payload.

    Args:
        key(bytes): 32-byte symmetric key.
        nonce(bytes): The 12-byte nonce used during encryption.
        ciphertext(bytes): Ciphertext including the GCM tag.

    Return:
        plaintext(bytes): The decrypted data.
    """
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def _challenge_message(nonce_b64: str, issue_ts: int) -> bytes:
    """Build the canonical challenge-signing message."""
    return f"{CHALLENGE_PREFIX}.{nonce_b64}.{issue_ts}".encode("utf-8")


def sign_challenge(secret: bytes, nonce_b64: str, issue_ts: int) -> str:
    """Sign a challenge with the server secret.

    Args:
        secret(bytes): Per-startup server secret.
        nonce_b64(str): Base64 nonce issued to the client.
        issue_ts(int): Unix timestamp the challenge was issued.

    Return:
        sig(str): Base64-encoded HMAC-SHA256 signature.
    """
    digest = hmac.new(secret, _challenge_message(nonce_b64, issue_ts), sha256).digest()
    return _b64e(digest)


def verify_challenge(secret: bytes, nonce_b64: str, issue_ts: int, sig: str) -> bool:
    """Verify a challenge signature in constant time.

    Args:
        secret(bytes): Per-startup server secret.
        nonce_b64(str): Base64 nonce from the client's token.
        issue_ts(int): Issue timestamp from the client's token.
        sig(str): Base64 signature from the client's token.

    Return:
        ok(bool): True if the signature is valid for this server secret.
    """
    expected = sign_challenge(secret, nonce_b64, issue_ts)
    return hmac.compare_digest(expected, sig)


def _proof_message(
    method: str, path: str, nonce_b64: str, issue_ts: int, client_pubkey_b64: str
) -> bytes:
    """Build the canonical API-key proof message."""
    return (
        f"{PROOF_PREFIX}.{method}.{path}.{nonce_b64}.{issue_ts}.{client_pubkey_b64}"
    ).encode("utf-8")


def compute_proof(
    apikey: str,
    method: str,
    path: str,
    nonce_b64: str,
    issue_ts: int,
    client_pubkey_b64: str,
) -> str:
    """Compute the API-key proof for a request.

    Args:
        apikey(str): The API key used as the HMAC secret.
        method(str): HTTP method (e.g. ``"GET"``).
        path(str): Endpoint path (e.g. ``"/cert"``).
        nonce_b64(str): Base64 challenge nonce.
        issue_ts(int): Challenge issue timestamp.
        client_pubkey_b64(str): Base64 of the client's ephemeral X25519 public key.

    Return:
        proof(str): Base64-encoded HMAC-SHA256 proof.
    """
    message = _proof_message(method, path, nonce_b64, issue_ts, client_pubkey_b64)
    digest = hmac.new(apikey.encode("utf-8"), message, sha256).digest()
    return _b64e(digest)


def verify_proof(
    proof: str,
    apikeys: list,
    method: str,
    path: str,
    nonce_b64: str,
    issue_ts: int,
    client_pubkey_b64: str,
) -> Optional[str]:
    """Verify an API-key proof against every configured key in constant time.

    All keys are checked (no early exit) to avoid leaking which key matched via timing.

    Args:
        proof(str): Base64 proof presented by the client.
        apikeys(list): Configured API keys.
        method(str): HTTP method of the request.
        path(str): Endpoint path of the request.
        nonce_b64(str): Base64 challenge nonce from the token.
        issue_ts(int): Challenge issue timestamp from the token.
        client_pubkey_b64(str): Base64 client ephemeral public key from the header.

    Return:
        matched(str|None): The matching API key, or None if no key matches.
    """
    matched: Optional[str] = None
    for apikey in apikeys:
        expected = compute_proof(
            apikey, method, path, nonce_b64, issue_ts, client_pubkey_b64
        )
        if hmac.compare_digest(expected, proof):
            matched = apikey
    return matched


def cert_key_match(cert_pem: bytes, key_pem: bytes) -> bool:
    """Check that a certificate and a private key form a coherent pair.

    Compares the certificate's public key with the public key derived from the private key
    by their SubjectPublicKeyInfo DER encoding.

    Args:
        cert_pem(bytes): PEM-encoded certificate (or fullchain; the leaf is used).
        key_pem(bytes): PEM-encoded private key.

    Return:
        match(bool): True if the certificate's public key matches the private key.

    Raises:
        ValueError: If either input cannot be parsed.
    """
    try:
        cert = load_pem_x509_certificate(cert_pem)
        cert_pub = cert.public_key()
    except Exception as exc:
        raise ValueError("could not parse certificate") from exc
    try:
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        key_pub = private_key.public_key()
    except Exception as exc:
        raise ValueError("could not parse private key") from exc

    def _spki(pub) -> Optional[bytes]:
        if isinstance(pub, Ed25519PublicKey):
            return pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        try:
            return pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception:
            return None

    cert_spki = _spki(cert_pub)
    key_spki = _spki(key_pub)
    if cert_spki is None or key_spki is None:
        return False
    return hmac.compare_digest(cert_spki, key_spki)
