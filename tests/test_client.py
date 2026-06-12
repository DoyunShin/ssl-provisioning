"""Tests for sslpv.services.client."""

import base64
import datetime
import http.client
import io
import os
import stat
import tempfile
import time
import urllib.request
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from sslpv.services.client import (
    _SafeRedirectHandler,
    build_opener,
    fetch_encrypted_pem,
    read_api_key,
    run_client,
    validate_server_url,
    write_pair_atomically,
)
from sslpv.utils import crypto


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_cert_key():
    """Generate a self-signed certificate and its matching private key (PEM bytes)."""
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


# ---------------------------------------------------------------------------
# validate_server_url
# ---------------------------------------------------------------------------


class TestValidateServerUrl:
    def test_accepts_https_with_port(self):
        result = validate_server_url("https://1.2.3.4:1243/")
        assert result == "https://1.2.3.4:1243"

    def test_accepts_https_hostname(self):
        result = validate_server_url("https://example.com")
        assert result == "https://example.com"

    def test_strips_path_query_fragment(self):
        result = validate_server_url("https://example.com/some/path?q=1#frag")
        assert result == "https://example.com"

    def test_normalizes_scheme_to_lowercase(self):
        result = validate_server_url("HTTPS://example.com/")
        assert result == "https://example.com"

    def test_rejects_http(self):
        with pytest.raises(ValueError, match="https"):
            validate_server_url("http://example.com/")

    def test_rejects_ftp(self):
        with pytest.raises(ValueError, match="https"):
            validate_server_url("ftp://example.com/")

    def test_rejects_userinfo_username(self):
        with pytest.raises(ValueError, match="userinfo"):
            validate_server_url("https://user@example.com/")

    def test_rejects_userinfo_username_password(self):
        with pytest.raises(ValueError, match="userinfo"):
            validate_server_url("https://user:pass@example.com/")

    def test_rejects_empty_netloc(self):
        with pytest.raises(ValueError, match="netloc"):
            validate_server_url("https:///path")

    def test_accepts_ipv6(self):
        result = validate_server_url("https://[::1]:8443/")
        assert result == "https://[::1]:8443"


# ---------------------------------------------------------------------------
# read_api_key
# ---------------------------------------------------------------------------


class TestReadApiKey:
    def test_reads_and_strips_whitespace(self, tmp_path):
        key_file = tmp_path / "api.key"
        key_file.write_text("  my-secret-key\n  ")
        key_file.chmod(0o600)
        assert read_api_key(str(key_file)) == "my-secret-key"

    def test_raises_on_missing_file(self, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            read_api_key(str(tmp_path / "nonexistent.key"))

    def test_raises_on_empty_file(self, tmp_path):
        key_file = tmp_path / "empty.key"
        key_file.write_text("   \n")
        key_file.chmod(0o600)
        with pytest.raises(ValueError, match="empty"):
            read_api_key(str(key_file))

    def test_warns_but_does_not_raise_on_group_readable(self, tmp_path):
        key_file = tmp_path / "loose.key"
        key_file.write_text("my-key")
        key_file.chmod(0o644)
        # Must not raise; a warning is emitted instead.
        result = read_api_key(str(key_file))
        assert result == "my-key"

    def test_warns_but_does_not_raise_on_other_readable(self, tmp_path):
        key_file = tmp_path / "world.key"
        key_file.write_text("other-key")
        key_file.chmod(0o604)
        result = read_api_key(str(key_file))
        assert result == "other-key"


# ---------------------------------------------------------------------------
# _SafeRedirectHandler
# ---------------------------------------------------------------------------


class TestSafeRedirectHandler:
    def _fake_response(self, headers_dict=None):
        """Build a minimal http.client.HTTPResponse-like object."""
        raw = b"HTTP/1.1 302 Found\r\n"
        if headers_dict:
            for k, v in headers_dict.items():
                raw += f"{k}: {v}\r\n".encode()
        raw += b"\r\n"
        sock = io.BytesIO(raw)

        class FakeSocket:
            def makefile(self, mode):
                return io.BytesIO(raw)

        resp = http.client.HTTPResponse(FakeSocket())
        resp.begin()
        return resp

    def _make_request(self, url: str) -> urllib.request.Request:
        return urllib.request.Request(url)

    def test_blocks_redirect_to_http(self):
        handler = _SafeRedirectHandler()
        req = self._make_request("https://example.com/")
        import urllib.error

        with pytest.raises((urllib.error.HTTPError, Exception)):
            handler.redirect_request(
                req, None, 302, "Found", {}, "http://evil.com/"
            )

    def test_allows_redirect_to_https(self):
        handler = _SafeRedirectHandler()
        req = self._make_request("https://example.com/")
        # redirect_request calls super() which tries to build a new Request;
        # for https it should not raise.
        try:
            result = handler.redirect_request(
                req, None, 302, "Found", {}, "https://other.example.com/"
            )
            # May return None or a Request depending on urllib internals.
            # The important thing is that no error is raised.
        except urllib.error.HTTPError:
            pytest.fail("https redirect should not be blocked")

    def test_blocks_redirect_to_ftp(self):
        handler = _SafeRedirectHandler()
        req = self._make_request("https://example.com/")
        import urllib.error

        with pytest.raises((urllib.error.HTTPError, Exception)):
            handler.redirect_request(
                req, None, 301, "Moved", {}, "ftp://files.example.com/"
            )


# ---------------------------------------------------------------------------
# write_pair_atomically
# ---------------------------------------------------------------------------


class TestWritePairAtomically:
    def test_writes_both_files_with_correct_contents(self, tmp_path):
        cert_path = str(tmp_path / "cert.pem")
        key_path = str(tmp_path / "key.pem")
        write_pair_atomically(cert_path, b"CERT", key_path, b"KEY")
        assert open(cert_path, "rb").read() == b"CERT"
        assert open(key_path, "rb").read() == b"KEY"

    def test_cert_mode_is_0644(self, tmp_path):
        cert_path = str(tmp_path / "cert.pem")
        key_path = str(tmp_path / "key.pem")
        write_pair_atomically(cert_path, b"CERT", key_path, b"KEY")
        mode = oct(os.stat(cert_path).st_mode & 0o777)
        assert mode == "0o644"

    def test_privkey_mode_is_0600(self, tmp_path):
        cert_path = str(tmp_path / "cert.pem")
        key_path = str(tmp_path / "key.pem")
        write_pair_atomically(cert_path, b"CERT", key_path, b"KEY")
        mode = oct(os.stat(key_path).st_mode & 0o777)
        assert mode == "0o600"

    def test_creates_missing_parent_directories(self, tmp_path):
        cert_path = str(tmp_path / "a" / "b" / "cert.pem")
        key_path = str(tmp_path / "c" / "d" / "key.pem")
        write_pair_atomically(cert_path, b"CERT", key_path, b"KEY")
        assert os.path.exists(cert_path)
        assert os.path.exists(key_path)

    def test_no_stray_temp_files_on_privkey_replace_failure(self, tmp_path):
        cert_path = str(tmp_path / "cert.pem")
        key_path = str(tmp_path / "key.pem")

        real_replace = os.replace
        replace_calls = []

        def patched_replace(src, dst):
            replace_calls.append((src, dst))
            if dst == key_path:
                raise OSError("simulated privkey rename failure")
            return real_replace(src, dst)

        with mock.patch("os.replace", side_effect=patched_replace):
            with pytest.raises(OSError, match="simulated privkey rename failure"):
                write_pair_atomically(cert_path, b"CERT", key_path, b"KEY")

        # No stray temp files should remain.
        remaining = list(tmp_path.iterdir())
        # cert.pem may or may not exist (it was rolled back); key.pem must not.
        assert not os.path.exists(key_path), "half-written privkey must not remain"
        tmp_files = [p for p in remaining if p.name not in ("cert.pem",)]
        assert all(not p.name.startswith("tmp") for p in tmp_files), (
            f"Stray temp files found: {tmp_files}"
        )


# ---------------------------------------------------------------------------
# run_client coherence integration
# ---------------------------------------------------------------------------


class TestRunClientCoherence:
    """Integration tests that monkeypatch fetch_encrypted_pem."""

    def _write_key_file(self, tmp_path: "Path", content: str = "test-api-key") -> str:
        key_file = tmp_path / "api.key"
        key_file.write_text(content)
        key_file.chmod(0o600)
        return str(key_file)

    def test_matching_pair_returns_0_and_writes_files(self, tmp_path):
        cert_pem, key_pem = make_cert_key()
        key_file = self._write_key_file(tmp_path)
        cert_path = str(tmp_path / "cert.pem")
        privkey_path = str(tmp_path / "key.pem")

        call_count = []

        def fake_fetch(opener, base, path, apikey, timeout):
            call_count.append(path)
            if path == "/cert":
                return cert_pem
            return key_pem

        with mock.patch(
            "sslpv.services.client.fetch_encrypted_pem", side_effect=fake_fetch
        ):
            result = run_client(
                server="https://example.com",
                key_path=key_file,
                cert_path=cert_path,
                privkey_path=privkey_path,
            )

        assert result == 0
        assert os.path.exists(cert_path)
        assert os.path.exists(privkey_path)
        assert open(cert_path, "rb").read() == cert_pem
        assert open(privkey_path, "rb").read() == key_pem

    def test_mismatched_pair_returns_nonzero_and_no_files_written(self, tmp_path):
        cert_pem, _ = make_cert_key()
        _, other_key_pem = make_cert_key()
        key_file = self._write_key_file(tmp_path)
        cert_path = str(tmp_path / "cert.pem")
        privkey_path = str(tmp_path / "key.pem")

        def fake_fetch(opener, base, path, apikey, timeout):
            if path == "/cert":
                return cert_pem
            return other_key_pem

        with mock.patch(
            "sslpv.services.client.fetch_encrypted_pem", side_effect=fake_fetch
        ):
            result = run_client(
                server="https://example.com",
                key_path=key_file,
                cert_path=cert_path,
                privkey_path=privkey_path,
            )

        assert result != 0
        assert not os.path.exists(cert_path), "cert must not be written on mismatch"
        assert not os.path.exists(privkey_path), "privkey must not be written on mismatch"

    def test_invalid_server_url_returns_nonzero(self, tmp_path):
        key_file = self._write_key_file(tmp_path)
        result = run_client(
            server="http://example.com",
            key_path=key_file,
            cert_path=str(tmp_path / "cert.pem"),
            privkey_path=str(tmp_path / "key.pem"),
        )
        assert result != 0

    def test_missing_key_file_returns_nonzero(self, tmp_path):
        result = run_client(
            server="https://example.com",
            key_path=str(tmp_path / "no_such_file.key"),
            cert_path=str(tmp_path / "cert.pem"),
            privkey_path=str(tmp_path / "key.pem"),
        )
        assert result != 0


# ---------------------------------------------------------------------------
# fetch_encrypted_pem real-crypto end-to-end
# ---------------------------------------------------------------------------

# A small but syntactically valid-looking PEM blob that round-trips through
# encrypt/decrypt without needing to be a real certificate.
_KNOWN_PEM = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAreallyshortfakebase64\n"
    b"encodedcertificatepayloadthatisnotvalidbutisgoodenoughtotestcrypto\n"
    b"-----END CERTIFICATE-----\n"
)

_TEST_APIKEY = "test-api-key-for-real-crypto"
_SERVER_SECRET = b"server-secret-32bytes-padding!!!"  # exactly 32 bytes


class TestFetchEncryptedPemRealCrypto:
    """Drive fetch_encrypted_pem against a fake fetch_json that performs
    real server-side crypto, so the entire client crypto path runs for real."""

    def _make_fake_fetch_json(self, path: str) -> object:
        """Return a fake_fetch_json callable that emulates the server for the
        given endpoint path.

        State (nonce, issue_ts, sig) generated during the challenge call is
        captured in a closure dict and reused when the cert/privkey endpoint
        is called, allowing proof verification to work correctly.
        """
        state: dict = {}

        def fake_fetch_json(
            opener: object,
            url: str,
            headers: dict,
            timeout: float,
        ) -> dict:
            if url.endswith("/challenge"):
                nonce = os.urandom(32)
                nonce_b64 = base64.b64encode(nonce).decode("ascii")
                issue_ts = int(time.time())
                sig = crypto.sign_challenge(_SERVER_SECRET, nonce_b64, issue_ts)
                state["nonce_b64"] = nonce_b64
                state["issue_ts"] = issue_ts
                return {
                    "status": 200,
                    "message": "ok",
                    "data": {
                        "nonce": nonce_b64,
                        "issue_ts": issue_ts,
                        "sig": sig,
                        "ttl": 60,
                    },
                }

            # The cert / privkey endpoint.
            client_pubkey_b64 = headers["X-Client-Pubkey"]

            # Verify the proof to confirm the client assembled it correctly.
            auth_header: str = headers["Authorization"]
            # Token format: "Bearer v1.<nonce_b64>.<issue_ts>.<sig_b64>.<proof_b64>"
            token_body = auth_header.removeprefix("Bearer ")
            parts = token_body.split(".", 4)
            # parts: ["v1", nonce_b64, issue_ts_str, sig_b64, proof_b64]
            proof_b64 = parts[4]
            matched = crypto.verify_proof(
                proof=proof_b64,
                apikeys=[_TEST_APIKEY],
                method="GET",
                path=path,
                nonce_b64=state["nonce_b64"],
                issue_ts=state["issue_ts"],
                client_pubkey_b64=client_pubkey_b64,
            )
            assert matched == _TEST_APIKEY, (
                f"Server-side proof verification failed for path {path!r}"
            )

            # Encrypt the payload with a fresh ephemeral server keypair.
            server_priv, server_pub_raw = crypto.generate_ephemeral_keypair()
            client_pub_raw = base64.b64decode(client_pubkey_b64)
            key = crypto.derive_shared_key(server_priv, client_pub_raw, _TEST_APIKEY)
            enc_nonce, ciphertext = crypto.encrypt_payload(key, _KNOWN_PEM)

            return {
                "status": 200,
                "message": "ok",
                "data": {
                    "server_pubkey": base64.b64encode(server_pub_raw).decode("ascii"),
                    "nonce": base64.b64encode(enc_nonce).decode("ascii"),
                    "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                },
            }

        return fake_fetch_json

    def test_fetch_encrypted_pem_real_crypto(self, monkeypatch):
        """fetch_encrypted_pem with real crypto: challenge -> proof -> encrypt -> decrypt."""
        fake = self._make_fake_fetch_json("/cert")
        monkeypatch.setattr("sslpv.services.client.fetch_json", fake)

        result = fetch_encrypted_pem(
            opener=object(),
            base="https://h:1",
            path="/cert",
            apikey=_TEST_APIKEY,
            timeout=5.0,
        )

        assert result == _KNOWN_PEM

    def test_fetch_encrypted_pem_wrong_apikey_fails_to_decrypt(self, monkeypatch):
        """A client using the wrong apikey cannot decrypt the server response."""
        fake = self._make_fake_fetch_json("/cert")
        monkeypatch.setattr("sslpv.services.client.fetch_json", fake)

        # Patch derive_shared_key inside the client so it uses a different key.
        original_derive = crypto.derive_shared_key

        def derive_with_wrong_key(
            private_key: object,
            peer_public: bytes,
            apikey: str,
        ) -> bytes:
            return original_derive(private_key, peer_public, "wrong-api-key")

        monkeypatch.setattr("sslpv.services.client.derive_shared_key", derive_with_wrong_key)

        with pytest.raises(Exception):
            fetch_encrypted_pem(
                opener=object(),
                base="https://h:1",
                path="/cert",
                apikey=_TEST_APIKEY,
                timeout=5.0,
            )
