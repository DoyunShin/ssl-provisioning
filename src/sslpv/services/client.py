"""Client-side SSL certificate provisioning logic.

Handles the full challenge-response protocol to retrieve an encrypted certificate
and private key from the sslpv server, then writes them to disk atomically.
"""

import base64
import hashlib
import http.client
import json
import logging
import os
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from sslpv.utils.crypto import (
    cert_key_match,
    compute_proof,
    decrypt_payload,
    derive_shared_key,
    generate_ephemeral_keypair,
)
from sslpv.utils.logging import print_message, setup_logging

logger = setup_logging(name="sslpv.client")


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------


def validate_server_url(server: str) -> str:
    """Validate and normalize the server base URL.

    Requires https scheme, non-empty netloc, and no userinfo component.
    Strips any path, query, or fragment from the URL.

    Args:
        server(str): Raw server URL supplied by the caller.

    Return:
        base_url(str): Normalized ``scheme://netloc`` string.

    Raises:
        ValueError: If the scheme is not https, the netloc is empty, or
            userinfo (username/password) is present in the URL.
    """
    parsed = urllib.parse.urlparse(server)

    if parsed.scheme.lower() != "https":
        raise ValueError(
            f"Server URL must use the https scheme (got {parsed.scheme!r}); "
            "non-https would expose the Authorization header in plaintext."
        )

    if not parsed.netloc:
        raise ValueError("Server URL must contain a non-empty host (netloc).")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "Server URL must not contain userinfo (username/password); "
            "use the API key file for authentication."
        )

    return f"{parsed.scheme.lower()}://{parsed.netloc}"


# ---------------------------------------------------------------------------
# API key reader
# ---------------------------------------------------------------------------


def read_api_key(key_path: str) -> str:
    """Read the API key from a file, stripping whitespace.

    Emits a warning (but does not raise) when the file is readable by
    group or other (mode bits other than user bits are set).

    Args:
        key_path(str): Path to the file containing the API key.

    Return:
        apikey(str): The API key string.

    Raises:
        ValueError: If the file does not exist, cannot be read, or is empty.
    """
    try:
        with open(key_path, "r") as fh:
            content = fh.read().strip()
    except FileNotFoundError:
        raise ValueError(f"API key file not found: {key_path!r}")
    except OSError as exc:
        raise ValueError(f"Cannot read API key file {key_path!r}: {exc}") from exc

    if not content:
        raise ValueError(f"API key file is empty: {key_path!r}")

    try:
        mode = os.stat(key_path).st_mode
        if mode & 0o077 != 0:
            print_message(
                f"Warning: API key file {key_path!r} is readable by group or other "
                f"(mode {oct(mode & 0o777)}). Restrict permissions to 0600.",
                "fg:ansiyellow",
            )
    except OSError:
        pass

    return content


# ---------------------------------------------------------------------------
# Custom HTTPS connection for cert pinning
# ---------------------------------------------------------------------------


def _make_pinned_connection_class(pin_sha256: str):
    """Create an HTTPSConnection subclass that enforces a SHA-256 cert fingerprint.

    Args:
        pin_sha256(str): Expected SHA-256 hex digest of the server's DER certificate.
            Colons are stripped before comparison; comparison is case-insensitive.

    Return:
        cls(type): A subclass of http.client.HTTPSConnection.
    """
    expected = pin_sha256.replace(":", "").lower()

    class PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            super().connect()
            der = self.sock.getpeercert(binary_form=True)
            actual = hashlib.sha256(der).hexdigest().lower()
            if actual != expected:
                raise ssl.SSLError(
                    f"Certificate fingerprint mismatch: "
                    f"expected {expected!r}, got {actual!r}"
                )

    return PinnedHTTPSConnection


# ---------------------------------------------------------------------------
# Redirect handler (blocks https -> http downgrade)
# ---------------------------------------------------------------------------


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that blocks any redirect to a non-https URL.

    This prevents an attacker from issuing a 302 redirect that would cause
    the client to replay the Authorization header over plain HTTP.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp,
        code: int,
        msg: str,
        headers,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme.lower() != "https":
            raise urllib.error.HTTPError(
                newurl,
                code,
                f"Blocked redirect to non-https URL: {newurl!r}",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ---------------------------------------------------------------------------
# Opener builder
# ---------------------------------------------------------------------------


def build_opener(
    insecure: bool = False,
    ca_cert: Optional[str] = None,
    pin_sha256: Optional[str] = None,
) -> urllib.request.OpenerDirector:
    """Build a urllib OpenerDirector with TLS configuration and redirect safety.

    When ``pin_sha256`` is provided, trust is established by fingerprint and
    chain verification is relaxed. When ``insecure`` is set, chain verification
    is also disabled (dangerous — prints a loud warning).

    Args:
        insecure(bool): Disable certificate chain and hostname verification.
        ca_cert(str, optional): Path to a PEM CA bundle to use for verification.
        pin_sha256(str, optional): Expected SHA-256 hex fingerprint of the server
            leaf certificate (colons optional, case-insensitive).

    Return:
        opener(urllib.request.OpenerDirector): Configured opener.
    """
    if pin_sha256:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        conn_class = _make_pinned_connection_class(pin_sha256)

        class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
            def https_open(self, req):
                return self.do_open(conn_class, req, context=ctx)

        https_handler = PinnedHTTPSHandler(context=ctx)
    elif insecure:
        print_message(
            "Warning: TLS certificate verification is DISABLED (--insecure). "
            "The connection is not authenticated and is vulnerable to MITM attacks.",
            "fg:ansired",
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        https_handler = urllib.request.HTTPSHandler(context=ctx)
    else:
        ctx = ssl.create_default_context()
        if ca_cert:
            ctx.load_verify_locations(ca_cert)
        https_handler = urllib.request.HTTPSHandler(context=ctx)

    redirect_handler = _SafeRedirectHandler()
    return urllib.request.build_opener(redirect_handler, https_handler)


# ---------------------------------------------------------------------------
# JSON fetcher
# ---------------------------------------------------------------------------


def fetch_json(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: dict,
    timeout: float = 30.0,
) -> dict:
    """Perform a GET request and return the parsed JSON envelope.

    Args:
        opener(OpenerDirector): urllib opener to use for the request.
        url(str): Full URL to request.
        headers(dict): Additional HTTP headers to send.
        timeout(float): Request timeout in seconds.

    Return:
        envelope(dict): Parsed JSON object from the response body.

    Raises:
        RuntimeError: If the HTTP request fails or the envelope status != 200.
        ValueError: If the response body is not valid JSON.
    """
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            envelope = json.loads(body)
            status = envelope.get("status", exc.code)
            message = envelope.get("message", exc.reason)
        except (ValueError, AttributeError):
            status = exc.code
            message = exc.reason
        raise RuntimeError(
            f"Server returned HTTP {status}: {message}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request to {url!r} failed: {exc.reason}") from exc

    try:
        envelope = json.loads(body)
    except ValueError as exc:
        raise ValueError(f"Invalid JSON in response from {url!r}") from exc

    status = envelope.get("status")
    if status != 200:
        message = envelope.get("message", "<no message>")
        raise RuntimeError(f"Server returned status {status}: {message}")

    return envelope


# ---------------------------------------------------------------------------
# Challenge -> proof -> fetch -> decrypt for one endpoint
# ---------------------------------------------------------------------------


def fetch_encrypted_pem(
    opener: urllib.request.OpenerDirector,
    base: str,
    path: str,
    apikey: str,
    timeout: float,
) -> bytes:
    """Fetch, decrypt, and return PEM bytes for a single endpoint.

    Performs the full challenge-response flow:
    1. GET ``{base}/challenge`` to obtain a signed nonce.
    2. Generate an ephemeral X25519 keypair.
    3. Compute a proof binding the apikey to the challenge and the keypair.
    4. GET ``{base}{path}`` with the Authorization token and pubkey header.
    5. Decrypt the encrypted response using the shared key.

    Args:
        opener(OpenerDirector): urllib opener with TLS configuration applied.
        base(str): Normalized server base URL (no trailing slash).
        path(str): Endpoint path, e.g. ``"/cert"`` or ``"/privkey"``.
        apikey(str): The API key used for proof computation and key derivation.
        timeout(float): Per-request timeout in seconds.

    Return:
        pem_bytes(bytes): Decrypted PEM content returned by the server.

    Raises:
        RuntimeError: On any HTTP or protocol error.
        ValueError: If the server response cannot be parsed.
    """
    challenge_url = f"{base}/challenge"
    logger.info("Fetching challenge from %s", challenge_url)
    challenge_envelope = fetch_json(opener, challenge_url, {}, timeout)
    challenge_data = challenge_envelope["data"]

    nonce_b64: str = challenge_data["nonce"]
    issue_ts: int = challenge_data["issue_ts"]
    sig_b64: str = challenge_data["sig"]

    client_priv, client_pub_raw = generate_ephemeral_keypair()
    client_pubkey_b64 = base64.b64encode(client_pub_raw).decode("ascii")

    proof_b64 = compute_proof(apikey, "GET", path, nonce_b64, issue_ts, client_pubkey_b64)

    token = f"Bearer v1.{nonce_b64}.{issue_ts}.{sig_b64}.{proof_b64}"
    headers = {
        "Authorization": token,
        "X-Client-Pubkey": client_pubkey_b64,
    }

    endpoint_url = f"{base}{path}"
    logger.info("Fetching encrypted payload from %s", endpoint_url)
    payload_envelope = fetch_json(opener, endpoint_url, headers, timeout)
    payload_data = payload_envelope["data"]

    server_pubkey_b64: str = payload_data["server_pubkey"]
    enc_nonce_b64: str = payload_data["nonce"]
    ciphertext_b64: str = payload_data["ciphertext"]

    server_pub_raw = base64.b64decode(server_pubkey_b64)
    enc_nonce = base64.b64decode(enc_nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    key = derive_shared_key(client_priv, server_pub_raw, apikey)
    pem_bytes = decrypt_payload(key, enc_nonce, ciphertext)

    logger.info("Successfully decrypted payload from %s", endpoint_url)
    return pem_bytes


# ---------------------------------------------------------------------------
# Atomic writer
# ---------------------------------------------------------------------------


def write_pair_atomically(
    cert_path: str,
    cert_bytes: bytes,
    privkey_path: str,
    privkey_bytes: bytes,
) -> None:
    """Write a certificate and private key to disk atomically.

    Creates parent directories if they do not exist. Each file is written to a
    temporary file in the same directory, fsynced, given the correct permissions
    (cert 0o644, privkey 0o600), then renamed into place via ``os.replace``.

    If the second rename fails, an attempt is made to roll back or clean up so
    that a half-updated pair never persists.

    Args:
        cert_path(str): Destination path for the PEM certificate.
        cert_bytes(bytes): PEM bytes of the certificate.
        privkey_path(str): Destination path for the PEM private key.
        privkey_bytes(bytes): PEM bytes of the private key.

    Raises:
        OSError: If a write, fsync, or rename operation fails.
    """
    cert_dir = os.path.dirname(os.path.abspath(cert_path)) or "."
    privkey_dir = os.path.dirname(os.path.abspath(privkey_path)) or "."
    os.makedirs(cert_dir, exist_ok=True)
    os.makedirs(privkey_dir, exist_ok=True)

    cert_tmp_path: Optional[str] = None
    privkey_tmp_path: Optional[str] = None

    try:
        # Write certificate to a temporary file.
        cert_fd, cert_tmp_path = tempfile.mkstemp(dir=cert_dir)
        try:
            os.write(cert_fd, cert_bytes)
            os.fsync(cert_fd)
            os.fchmod(cert_fd, 0o644)
        finally:
            os.close(cert_fd)

        # Write private key to a temporary file.
        privkey_fd, privkey_tmp_path = tempfile.mkstemp(dir=privkey_dir)
        try:
            os.write(privkey_fd, privkey_bytes)
            os.fsync(privkey_fd)
            os.fchmod(privkey_fd, 0o600)
        finally:
            os.close(privkey_fd)

        # Rename cert into place first.
        os.replace(cert_tmp_path, cert_path)
        cert_tmp_path = None  # Successfully placed; no cleanup needed.

        # Rename privkey into place.
        try:
            os.replace(privkey_tmp_path, privkey_path)
            privkey_tmp_path = None
        except OSError:
            # The privkey rename failed; attempt to undo the cert rename.
            try:
                os.remove(cert_path)
            except OSError:
                pass
            raise

    except Exception:
        # Clean up any remaining temporary files.
        for tmp in (cert_tmp_path, privkey_tmp_path):
            if tmp is not None:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        raise


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------


def run_client(
    server: str,
    key_path: str,
    cert_path: str,
    privkey_path: str,
    insecure: bool = False,
    ca_cert: Optional[str] = None,
    pin_sha256: Optional[str] = None,
    timeout: float = 30.0,
) -> int:
    """Provision a certificate and private key from the sslpv server.

    Validates the server URL, reads the API key, fetches and decrypts both
    the certificate and the private key, verifies they form a coherent pair,
    and writes them atomically to disk.

    Args:
        server(str): Server base URL (must be https).
        key_path(str): Path to the file containing the API key.
        cert_path(str): Destination path for the PEM certificate.
        privkey_path(str): Destination path for the PEM private key.
        insecure(bool): Disable TLS certificate verification (dangerous).
        ca_cert(str, optional): Path to a custom CA bundle for verification.
        pin_sha256(str, optional): Expected SHA-256 fingerprint of the server cert.
        timeout(float): Per-request timeout in seconds.

    Return:
        exit_code(int): 0 on success, 1 on any failure.
    """
    try:
        # Stage 1: Validate inputs.
        base = validate_server_url(server)
        apikey = read_api_key(key_path)
        opener = build_opener(insecure=insecure, ca_cert=ca_cert, pin_sha256=pin_sha256)

        # Stage 2: Fetch certificate (fresh challenge).
        cert_pem = fetch_encrypted_pem(opener, base, "/cert", apikey, timeout)

        # Stage 3: Fetch private key (fresh challenge — do NOT reuse the nonce).
        privkey_pem = fetch_encrypted_pem(opener, base, "/privkey", apikey, timeout)

        # Stage 4: Verify the pair is coherent before writing anything.
        try:
            if not cert_key_match(cert_pem, privkey_pem):
                print_message(
                    "Error: Certificate and private key do not match. "
                    "No files have been written.",
                    "fg:ansired",
                )
                return 1
        except ValueError as exc:
            print_message(
                f"Error: Could not verify certificate/key pair: {exc}. "
                "No files have been written.",
                "fg:ansired",
            )
            return 1

        # Stage 5: Write atomically.
        write_pair_atomically(cert_path, cert_pem, privkey_path, privkey_pem)

        print_message(
            f"[OK] Certificate written to {cert_path!r} and "
            f"private key written to {privkey_path!r}.",
            "fg:ansigreen",
        )
        return 0

    except Exception as exc:
        print_message(f"Error: {exc}", "fg:ansired")
        logger.debug("run_client failed", exc_info=True)
        return 1
