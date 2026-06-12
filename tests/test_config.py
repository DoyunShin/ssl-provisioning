"""Tests for sslpv.models.config and sslpv.services.config."""

import datetime
import json
import os
import stat
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sslpv.models.config import ServerConfig
from sslpv.services.config import load_server_config


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
    """Write data to path with mode 0600.

    Args:
        path(str): Destination file path.
        data(bytes | str): Content to write.
    """
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as fh:
        fh.write(data)
    os.chmod(path, 0o600)


class TestServerConfigModel:
    """Tests for ServerConfig pydantic model."""

    def test_defaults(self) -> None:
        config = ServerConfig(
            fullchain="/etc/ssl/fullchain.pem",
            privkey="/etc/ssl/privkey.pem",
            apikeys=["key1"],
        )
        assert config.host == "0.0.0.0"
        assert config.port == 1243
        assert config.server_certfile is None
        assert config.server_keyfile is None
        assert config.trusted_proxies == []

    def test_tls_certfile_falls_back_to_fullchain(self) -> None:
        config = ServerConfig(
            fullchain="/etc/ssl/fullchain.pem",
            privkey="/etc/ssl/privkey.pem",
            apikeys=["key1"],
        )
        assert config.tls_certfile == "/etc/ssl/fullchain.pem"
        assert config.tls_keyfile == "/etc/ssl/privkey.pem"

    def test_tls_certfile_uses_override(self) -> None:
        config = ServerConfig(
            fullchain="/etc/ssl/fullchain.pem",
            privkey="/etc/ssl/privkey.pem",
            apikeys=["key1"],
            server_certfile="/srv/tls/server.crt",
            server_keyfile="/srv/tls/server.key",
        )
        assert config.tls_certfile == "/srv/tls/server.crt"
        assert config.tls_keyfile == "/srv/tls/server.key"


class TestLoadServerConfig:
    """Tests for load_server_config validation."""

    def setup_method(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        cert_pem, key_pem = make_cert_key()
        self.cert_path = os.path.join(self._tmpdir, "fullchain.pem")
        self.key_path = os.path.join(self._tmpdir, "privkey.pem")
        write_600(self.cert_path, cert_pem)
        write_600(self.key_path, key_pem)

    def _write_config(self, data: dict, path: str | None = None, mode: int = 0o600) -> str:
        cfg_path = path or os.path.join(self._tmpdir, "config.json")
        with open(cfg_path, "w") as fh:
            json.dump(data, fh)
        os.chmod(cfg_path, mode)
        return cfg_path

    def _default_data(self) -> dict:
        return {
            "fullchain": self.cert_path,
            "privkey": self.key_path,
            "apikeys": ["testkey"],
        }

    def test_valid_config_loads(self) -> None:
        cfg_path = self._write_config(self._default_data())
        config = load_server_config(cfg_path)
        assert config.apikeys == ["testkey"]
        assert config.fullchain == self.cert_path

    def test_group_readable_config_raises(self) -> None:
        cfg_path = self._write_config(self._default_data(), mode=0o640)
        with pytest.raises(ValueError, match="chmod 600"):
            load_server_config(cfg_path)

    def test_other_readable_config_raises(self) -> None:
        cfg_path = self._write_config(self._default_data(), mode=0o604)
        with pytest.raises(ValueError, match="chmod 600"):
            load_server_config(cfg_path)

    def test_missing_cert_file_raises(self) -> None:
        data = self._default_data()
        data["fullchain"] = "/nonexistent/fullchain.pem"
        cfg_path = self._write_config(data)
        with pytest.raises(ValueError):
            load_server_config(cfg_path)

    def test_missing_privkey_file_raises(self) -> None:
        data = self._default_data()
        data["privkey"] = "/nonexistent/privkey.pem"
        cfg_path = self._write_config(data)
        with pytest.raises(ValueError):
            load_server_config(cfg_path)

    def test_empty_apikeys_raises(self) -> None:
        data = self._default_data()
        data["apikeys"] = []
        cfg_path = self._write_config(data)
        with pytest.raises(ValueError, match="apikeys"):
            load_server_config(cfg_path)

    def test_whitespace_apikey_raises(self) -> None:
        data = self._default_data()
        data["apikeys"] = ["   "]
        cfg_path = self._write_config(data)
        with pytest.raises(ValueError, match="whitespace"):
            load_server_config(cfg_path)

    def test_empty_string_apikey_raises(self) -> None:
        data = self._default_data()
        data["apikeys"] = [""]
        cfg_path = self._write_config(data)
        with pytest.raises(ValueError, match="whitespace"):
            load_server_config(cfg_path)

    def test_server_certfile_keyfile_override(self) -> None:
        cert_pem2, key_pem2 = make_cert_key()
        cert2 = os.path.join(self._tmpdir, "server_cert.pem")
        key2 = os.path.join(self._tmpdir, "server_key.pem")
        write_600(cert2, cert_pem2)
        write_600(key2, key_pem2)

        data = self._default_data()
        data["server_certfile"] = cert2
        data["server_keyfile"] = key2
        cfg_path = self._write_config(data)
        config = load_server_config(cfg_path)
        assert config.tls_certfile == cert2
        assert config.tls_keyfile == key2

    def test_server_certfile_missing_raises(self) -> None:
        data = self._default_data()
        data["server_certfile"] = "/nonexistent/server.crt"
        cfg_path = self._write_config(data)
        with pytest.raises(ValueError):
            load_server_config(cfg_path)
