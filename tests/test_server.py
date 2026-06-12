"""Integration tests for the sslpv server endpoints."""

import base64
import datetime
import json
import os
import tempfile
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from sslpv.models.config import ServerConfig
from sslpv.services.server import RateLimiter, SpentNonceSet, create_app
from sslpv.utils.crypto import (
    compute_proof,
    decrypt_payload,
    generate_ephemeral_keypair,
    sign_challenge,
)


def make_cert_key() -> tuple[bytes, bytes]:
    """Generate a self-signed RSA-2048 certificate and private key pair.

    Return:
        pair(tuple): ``(cert_pem, key_pem)`` as bytes.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def write_600(path: str, data: bytes | str) -> None:
    """Write data to path with mode 0600."""
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as fh:
        fh.write(data)
    os.chmod(path, 0o600)


@pytest.fixture(scope="module")
def tmp_pem_dir():
    """Module-scoped temp directory containing cert and key PEM files."""
    with tempfile.TemporaryDirectory() as d:
        cert_pem, key_pem = make_cert_key()
        cert_path = os.path.join(d, "fullchain.pem")
        key_path = os.path.join(d, "privkey.pem")
        write_600(cert_path, cert_pem)
        write_600(key_path, key_pem)
        yield {"dir": d, "cert": cert_path, "key": key_path, "cert_pem": cert_pem, "key_pem": key_pem}


@pytest.fixture
def app_and_client(tmp_pem_dir):
    """Create a fresh app + TestClient for each test."""
    config = ServerConfig(
        fullchain=tmp_pem_dir["cert"],
        privkey=tmp_pem_dir["key"],
        apikeys=["test-apikey-1"],
    )
    app = create_app(config)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield app, client, tmp_pem_dir


def _build_token(
    server_secret: bytes,
    apikey: str,
    method: str,
    path: str,
    client_pub_raw: bytes,
    nonce_b64: str | None = None,
    issue_ts: int | None = None,
) -> tuple[str, str]:
    """Build a valid Bearer token and client pubkey header.

    Return:
        result(tuple): ``(authorization_header_value, client_pubkey_b64)``.
    """
    if nonce_b64 is None:
        nonce_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    if issue_ts is None:
        issue_ts = int(time.time())

    client_pubkey_b64 = base64.b64encode(client_pub_raw).decode("ascii")
    sig = sign_challenge(server_secret, nonce_b64, issue_ts)
    proof = compute_proof(apikey, method, path, nonce_b64, issue_ts, client_pubkey_b64)

    token = f"Bearer v1.{nonce_b64}.{issue_ts}.{sig}.{proof}"
    return token, client_pubkey_b64


class TestChallenge:
    """Tests for GET /challenge."""

    def test_challenge_returns_required_fields(self, app_and_client) -> None:
        _, client, _ = app_and_client
        resp = client.get("/challenge")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == 200
        data = body["data"]
        assert "nonce" in data
        assert "issue_ts" in data
        assert "sig" in data
        assert data["ttl"] == 60

    def test_challenge_nonce_is_base64(self, app_and_client) -> None:
        _, client, _ = app_and_client
        resp = client.get("/challenge")
        nonce_b64 = resp.json()["data"]["nonce"]
        decoded = base64.b64decode(nonce_b64, validate=True)
        assert len(decoded) == 32


class TestGetCert:
    """Tests for GET /cert."""

    def test_happy_path_cert(self, app_and_client) -> None:
        app, client, tmp = app_and_client
        server_secret = app.state.server_secret
        client_priv, client_pub_raw = generate_ephemeral_keypair()
        auth, pubkey_b64 = _build_token(server_secret, "test-apikey-1", "GET", "/cert", client_pub_raw)

        resp = client.get("/cert", headers={"Authorization": auth, "X-Client-Pubkey": pubkey_b64})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == 200
        data = body["data"]

        # Decrypt and verify we get the original cert PEM back
        server_pub_raw = base64.b64decode(data["server_pubkey"])
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])

        from sslpv.utils.crypto import derive_shared_key
        key = derive_shared_key(client_priv, server_pub_raw, "test-apikey-1")
        plaintext = decrypt_payload(key, nonce, ciphertext)
        assert plaintext == tmp["cert_pem"]

    def test_one_time_use_nonce(self, app_and_client) -> None:
        app, client, _ = app_and_client
        server_secret = app.state.server_secret
        client_priv, client_pub_raw = generate_ephemeral_keypair()

        nonce_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
        issue_ts = int(time.time())
        auth, pubkey_b64 = _build_token(
            server_secret, "test-apikey-1", "GET", "/cert", client_pub_raw,
            nonce_b64=nonce_b64, issue_ts=issue_ts,
        )

        resp1 = client.get("/cert", headers={"Authorization": auth, "X-Client-Pubkey": pubkey_b64})
        assert resp1.status_code == 200

        # Reuse the same token -> nonce is spent -> 401
        resp2 = client.get("/cert", headers={"Authorization": auth, "X-Client-Pubkey": pubkey_b64})
        assert resp2.status_code == 401

    def test_failed_proof_does_not_spend_nonce(self, app_and_client) -> None:
        """A bad proof must NOT consume the nonce; a subsequent valid request must succeed."""
        app, client, _ = app_and_client
        server_secret = app.state.server_secret
        client_priv, client_pub_raw = generate_ephemeral_keypair()
        pubkey_b64 = base64.b64encode(client_pub_raw).decode("ascii")

        nonce_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
        issue_ts = int(time.time())
        sig = sign_challenge(server_secret, nonce_b64, issue_ts)

        # Bad proof token
        bad_proof = base64.b64encode(b"not-a-valid-proof").decode("ascii")
        bad_token = f"Bearer v1.{nonce_b64}.{issue_ts}.{sig}.{bad_proof}"

        resp_bad = client.get(
            "/cert", headers={"Authorization": bad_token, "X-Client-Pubkey": pubkey_b64}
        )
        assert resp_bad.status_code == 401

        # Valid token with the SAME nonce -> should still work
        good_proof = compute_proof("test-apikey-1", "GET", "/cert", nonce_b64, issue_ts, pubkey_b64)
        good_token = f"Bearer v1.{nonce_b64}.{issue_ts}.{sig}.{good_proof}"

        resp_good = client.get(
            "/cert", headers={"Authorization": good_token, "X-Client-Pubkey": pubkey_b64}
        )
        assert resp_good.status_code == 200

    def test_forged_sig_raises_401(self, app_and_client) -> None:
        app, client, _ = app_and_client
        _, client_pub_raw = generate_ephemeral_keypair()
        pubkey_b64 = base64.b64encode(client_pub_raw).decode("ascii")

        nonce_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
        issue_ts = int(time.time())
        fake_sig = base64.b64encode(b"fakesig").decode("ascii")
        fake_proof = base64.b64encode(b"fakeproof").decode("ascii")
        token = f"Bearer v1.{nonce_b64}.{issue_ts}.{fake_sig}.{fake_proof}"

        resp = client.get("/cert", headers={"Authorization": token, "X-Client-Pubkey": pubkey_b64})
        assert resp.status_code == 401

    def test_expired_issue_ts_raises_401(self, app_and_client) -> None:
        app, client, _ = app_and_client
        server_secret = app.state.server_secret
        _, client_pub_raw = generate_ephemeral_keypair()

        issue_ts = int(time.time()) - 120  # 2 minutes ago
        nonce_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
        auth, pubkey_b64 = _build_token(
            server_secret, "test-apikey-1", "GET", "/cert", client_pub_raw,
            nonce_b64=nonce_b64, issue_ts=issue_ts,
        )

        resp = client.get("/cert", headers={"Authorization": auth, "X-Client-Pubkey": pubkey_b64})
        assert resp.status_code == 401

    def test_future_issue_ts_raises_401(self, app_and_client) -> None:
        app, client, _ = app_and_client
        server_secret = app.state.server_secret
        _, client_pub_raw = generate_ephemeral_keypair()

        issue_ts = int(time.time()) + 100  # 100 seconds in the future
        nonce_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
        auth, pubkey_b64 = _build_token(
            server_secret, "test-apikey-1", "GET", "/cert", client_pub_raw,
            nonce_b64=nonce_b64, issue_ts=issue_ts,
        )

        resp = client.get("/cert", headers={"Authorization": auth, "X-Client-Pubkey": pubkey_b64})
        assert resp.status_code == 401

    def test_path_binding_cert_proof_on_privkey_fails(self, app_and_client) -> None:
        """Proof computed for /cert must NOT be accepted on /privkey."""
        app, client, _ = app_and_client
        server_secret = app.state.server_secret
        _, client_pub_raw = generate_ephemeral_keypair()

        # Build token bound to /cert
        auth, pubkey_b64 = _build_token(
            server_secret, "test-apikey-1", "GET", "/cert", client_pub_raw
        )

        resp = client.get(
            "/privkey", headers={"Authorization": auth, "X-Client-Pubkey": pubkey_b64}
        )
        assert resp.status_code == 401

    def test_missing_client_pubkey_raises_400(self, app_and_client) -> None:
        app, client, _ = app_and_client
        server_secret = app.state.server_secret
        _, client_pub_raw = generate_ephemeral_keypair()
        auth, _ = _build_token(server_secret, "test-apikey-1", "GET", "/cert", client_pub_raw)

        resp = client.get("/cert", headers={"Authorization": auth})
        assert resp.status_code == 400

    def test_invalid_client_pubkey_raises_400(self, app_and_client) -> None:
        app, client, _ = app_and_client
        server_secret = app.state.server_secret
        _, client_pub_raw = generate_ephemeral_keypair()
        auth, _ = _build_token(server_secret, "test-apikey-1", "GET", "/cert", client_pub_raw)

        resp = client.get(
            "/cert",
            headers={"Authorization": auth, "X-Client-Pubkey": "not-valid-base64!!!"},
        )
        assert resp.status_code == 400

    def test_short_pubkey_raises_400(self, app_and_client) -> None:
        app, client, _ = app_and_client
        server_secret = app.state.server_secret
        _, client_pub_raw = generate_ephemeral_keypair()
        auth, _ = _build_token(server_secret, "test-apikey-1", "GET", "/cert", client_pub_raw)

        short = base64.b64encode(b"tooshort").decode("ascii")
        resp = client.get(
            "/cert", headers={"Authorization": auth, "X-Client-Pubkey": short}
        )
        assert resp.status_code == 400


class TestGetPrivkey:
    """Tests for GET /privkey."""

    def test_happy_path_privkey(self, app_and_client) -> None:
        app, client, tmp = app_and_client
        server_secret = app.state.server_secret
        client_priv, client_pub_raw = generate_ephemeral_keypair()
        auth, pubkey_b64 = _build_token(
            server_secret, "test-apikey-1", "GET", "/privkey", client_pub_raw
        )

        resp = client.get(
            "/privkey", headers={"Authorization": auth, "X-Client-Pubkey": pubkey_b64}
        )
        assert resp.status_code == 200
        data = resp.json()["data"]

        server_pub_raw = base64.b64decode(data["server_pubkey"])
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])

        from sslpv.utils.crypto import derive_shared_key
        key = derive_shared_key(client_priv, server_pub_raw, "test-apikey-1")
        plaintext = decrypt_payload(key, nonce, ciphertext)
        assert plaintext == tmp["key_pem"]


class TestDocsDisabled:
    """Verify that auto-generated API docs are not exposed."""

    def test_docs_returns_404(self, app_and_client) -> None:
        _, client, _ = app_and_client
        resp = client.get("/docs")
        assert resp.status_code == 404

    def test_openapi_json_returns_404(self, app_and_client) -> None:
        _, client, _ = app_and_client
        resp = client.get("/openapi.json")
        assert resp.status_code == 404

    def test_redoc_returns_404(self, app_and_client) -> None:
        _, client, _ = app_and_client
        resp = client.get("/redoc")
        assert resp.status_code == 404


class TestRateLimiter:
    """Unit tests for RateLimiter."""

    def test_allows_up_to_capacity(self) -> None:
        limiter = RateLimiter(rate=0.0, capacity=3)
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is False

    def test_refill_over_time(self) -> None:
        tick = [0.0]

        def now() -> float:
            return tick[0]

        limiter = RateLimiter(rate=1.0, capacity=1, _now=now)
        assert limiter.allow("10.0.0.1") is True
        assert limiter.allow("10.0.0.1") is False
        tick[0] = 1.5  # 1.5 tokens refilled; capacity=1 so only 1 available
        assert limiter.allow("10.0.0.1") is True
        assert limiter.allow("10.0.0.1") is False

    def test_different_ips_are_independent(self) -> None:
        limiter = RateLimiter(rate=0.0, capacity=1)
        assert limiter.allow("1.1.1.1") is True
        assert limiter.allow("2.2.2.2") is True
        assert limiter.allow("1.1.1.1") is False
        assert limiter.allow("2.2.2.2") is False

    def test_rate_limit_endpoint_returns_429(self, app_and_client) -> None:
        import time as _time

        app, client, _ = app_and_client
        # Drain the bucket for the TestClient IP ("testclient") by setting tokens=0
        app.state.rate_limiter._buckets["testclient"] = [0.0, _time.monotonic()]
        resp = client.get("/challenge")
        assert resp.status_code == 429
        assert resp.json()["status"] == 429


class TestSpentNonceSet:
    """Unit tests for SpentNonceSet."""

    def test_add_and_contains(self) -> None:
        store = SpentNonceSet()
        future = int(time.time()) + 60
        store.add("nonce1", future)
        assert store.contains("nonce1") is True

    def test_expired_nonce_is_absent(self) -> None:
        store = SpentNonceSet()
        past = int(time.time()) - 1
        store.add("nonce_old", past)
        assert store.contains("nonce_old") is False

    def test_unknown_nonce_is_absent(self) -> None:
        store = SpentNonceSet()
        assert store.contains("nosuchnonce") is False

    def test_purge_removes_expired(self) -> None:
        store = SpentNonceSet()
        future = int(time.time()) + 60
        past = int(time.time()) - 1
        store.add("fresh", future)
        store.add("stale", past)
        store.purge(int(time.time()))
        assert store.contains("fresh") is True
        assert store.contains("stale") is False

    def test_max_size_evicts_oldest(self) -> None:
        store = SpentNonceSet(max_size=2)
        future = int(time.time()) + 60
        store.add("a", future)
        store.add("b", future)
        store.add("c", future)  # should evict "a"
        assert store.contains("a") is False
        assert store.contains("b") is True
        assert store.contains("c") is True
