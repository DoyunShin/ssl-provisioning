"""Tests for sslpv.main CLI entry point."""

import pytest

import sslpv.main as cli_module
from sslpv.main import build_parser, main


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def test_build_parser_server_subcommand():
    parser = build_parser()
    args = parser.parse_args(["server", "--config", "/etc/sslpv/config.json"])
    assert args.subcommand == "server"
    assert args.config == "/etc/sslpv/config.json"


def test_build_parser_client_subcommand_required_args():
    parser = build_parser()
    args = parser.parse_args([
        "client",
        "--server", "https://example.com:1243",
        "--key", "/run/secrets/apikey",
        "--cert", "/etc/ssl/fullchain.pem",
        "--privkey", "/etc/ssl/privkey.pem",
    ])
    assert args.subcommand == "client"
    assert args.server == "https://example.com:1243"
    assert args.key == "/run/secrets/apikey"
    assert args.cert == "/etc/ssl/fullchain.pem"
    assert args.privkey == "/etc/ssl/privkey.pem"
    assert args.insecure is False
    assert args.ca_cert is None
    assert args.pin_sha256 is None
    assert args.timeout == 30.0
    assert args.post_hook is None
    assert args.hook_on_change is False


def test_build_parser_client_subcommand_optional_args():
    parser = build_parser()
    args = parser.parse_args([
        "client",
        "--server", "https://192.0.2.1:1243",
        "--key", "/run/secrets/apikey",
        "--cert", "/tmp/fullchain.pem",
        "--privkey", "/tmp/privkey.pem",
        "--insecure",
        "--ca-cert", "/etc/ssl/ca.pem",
        "--pin-sha256", "ab:cd:ef:00",
        "--timeout", "60.0",
    ])
    assert args.insecure is True
    assert args.ca_cert == "/etc/ssl/ca.pem"
    assert args.pin_sha256 == "ab:cd:ef:00"
    assert args.timeout == 60.0


def test_build_parser_client_post_hook_flags():
    parser = build_parser()
    args = parser.parse_args([
        "client",
        "--server", "https://example.com:1243",
        "--key", "/run/secrets/apikey",
        "--cert", "/tmp/fullchain.pem",
        "--privkey", "/tmp/privkey.pem",
        "--post-hook", "echo hi",
        "--hook-on-change",
    ])
    assert args.post_hook == "echo hi"
    assert args.hook_on_change is True


def test_build_parser_client_post_hook_defaults():
    parser = build_parser()
    args = parser.parse_args([
        "client",
        "--server", "https://example.com:1243",
        "--key", "/run/secrets/apikey",
        "--cert", "/tmp/fullchain.pem",
        "--privkey", "/tmp/privkey.pem",
    ])
    assert args.post_hook is None
    assert args.hook_on_change is False


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------


def test_main_version_returns_zero(capsys):
    result = main(["--version"])
    assert result == 0


# ---------------------------------------------------------------------------
# No subcommand
# ---------------------------------------------------------------------------


def test_main_no_subcommand_returns_nonzero(capsys):
    result = main([])
    assert result != 0


# ---------------------------------------------------------------------------
# client subcommand dispatches to run_client
# ---------------------------------------------------------------------------


def test_main_client_dispatches_to_run_client(monkeypatch):
    sentinel = 42

    def fake_run_client(
        server,
        key_path,
        cert_path,
        privkey_path,
        insecure=False,
        ca_cert=None,
        pin_sha256=None,
        timeout=30.0,
        post_hook=None,
        hook_on_change=False,
    ):
        assert server == "https://example.com:1243"
        assert key_path == "/run/secrets/apikey"
        assert cert_path == "/out/fullchain.pem"
        assert privkey_path == "/out/privkey.pem"
        assert insecure is False
        assert ca_cert is None
        assert pin_sha256 is None
        assert timeout == 30.0
        assert post_hook is None
        assert hook_on_change is False
        return sentinel

    monkeypatch.setattr(cli_module, "run_client", fake_run_client)

    result = main([
        "client",
        "--server", "https://example.com:1243",
        "--key", "/run/secrets/apikey",
        "--cert", "/out/fullchain.pem",
        "--privkey", "/out/privkey.pem",
    ])
    assert result == sentinel


def test_main_client_optional_flags_passed_through(monkeypatch):
    captured = {}

    def fake_run_client(
        server,
        key_path,
        cert_path,
        privkey_path,
        insecure=False,
        ca_cert=None,
        pin_sha256=None,
        timeout=30.0,
        post_hook=None,
        hook_on_change=False,
    ):
        captured["insecure"] = insecure
        captured["ca_cert"] = ca_cert
        captured["pin_sha256"] = pin_sha256
        captured["timeout"] = timeout
        return 0

    monkeypatch.setattr(cli_module, "run_client", fake_run_client)

    main([
        "client",
        "--server", "https://192.0.2.1:1243",
        "--key", "/tmp/key",
        "--cert", "/tmp/cert.pem",
        "--privkey", "/tmp/privkey.pem",
        "--insecure",
        "--ca-cert", "/etc/ssl/ca.pem",
        "--pin-sha256", "deadbeef",
        "--timeout", "15.5",
    ])

    assert captured["insecure"] is True
    assert captured["ca_cert"] == "/etc/ssl/ca.pem"
    assert captured["pin_sha256"] == "deadbeef"
    assert captured["timeout"] == 15.5


def test_main_client_post_hook_flags_forwarded(monkeypatch):
    captured = {}

    def fake_run_client(
        server,
        key_path,
        cert_path,
        privkey_path,
        insecure=False,
        ca_cert=None,
        pin_sha256=None,
        timeout=30.0,
        post_hook=None,
        hook_on_change=False,
    ):
        captured["post_hook"] = post_hook
        captured["hook_on_change"] = hook_on_change
        return 0

    monkeypatch.setattr(cli_module, "run_client", fake_run_client)

    main([
        "client",
        "--server", "https://example.com:1243",
        "--key", "/tmp/key",
        "--cert", "/tmp/cert.pem",
        "--privkey", "/tmp/privkey.pem",
        "--post-hook", "systemctl reload nginx",
        "--hook-on-change",
    ])

    assert captured["post_hook"] == "systemctl reload nginx"
    assert captured["hook_on_change"] is True


def test_main_client_post_hook_defaults_forwarded(monkeypatch):
    captured = {}

    def fake_run_client(
        server,
        key_path,
        cert_path,
        privkey_path,
        insecure=False,
        ca_cert=None,
        pin_sha256=None,
        timeout=30.0,
        post_hook=None,
        hook_on_change=False,
    ):
        captured["post_hook"] = post_hook
        captured["hook_on_change"] = hook_on_change
        return 0

    monkeypatch.setattr(cli_module, "run_client", fake_run_client)

    main([
        "client",
        "--server", "https://example.com:1243",
        "--key", "/tmp/key",
        "--cert", "/tmp/cert.pem",
        "--privkey", "/tmp/privkey.pem",
    ])

    assert captured["post_hook"] is None
    assert captured["hook_on_change"] is False


# ---------------------------------------------------------------------------
# server subcommand dispatches to run_server
# ---------------------------------------------------------------------------


def test_main_server_dispatches_to_run_server(monkeypatch):
    called_with = {}

    def fake_run_server(config_path: str) -> None:
        called_with["config_path"] = config_path

    monkeypatch.setattr(cli_module, "run_server", fake_run_server)

    result = main(["server", "--config", "/etc/sslpv/config.json"])
    assert result == 0
    assert called_with["config_path"] == "/etc/sslpv/config.json"


def test_main_server_keyboard_interrupt_returns_zero(monkeypatch):
    def fake_run_server(config_path: str) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, "run_server", fake_run_server)

    result = main(["server", "--config", "x.json"])
    assert result == 0


def test_main_server_exception_returns_one(monkeypatch):
    def fake_run_server(config_path: str) -> None:
        raise RuntimeError("config error")

    monkeypatch.setattr(cli_module, "run_server", fake_run_server)

    result = main(["server", "--config", "bad.json"])
    assert result == 1
