"""CLI entry point for sslpv.

Provides two subcommands:
  sslpv server --config /path/to/config.json
  sslpv client --server URL --key PATH --cert PATH --privkey PATH [options]
"""

import argparse
import sys
from typing import Optional

from sslpv import __version__
from sslpv.services.client import run_client
from sslpv.services.server import run_server
from sslpv.utils.logging import print_message, setup_logging


def build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level argument parser.

    Return:
        parser(argparse.ArgumentParser): Configured argument parser with
            server and client subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="sslpv",
        description="SSL certificate provisioning tool.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        default=False,
        help="Print version and exit.",
    )

    subparsers = parser.add_subparsers(dest="subcommand")

    # server subcommand
    server_parser = subparsers.add_parser(
        "server",
        help="Run the sslpv provisioning server.",
    )
    server_parser.add_argument(
        "--config",
        required=True,
        metavar="PATH",
        help="Path to the JSON server config file.",
    )

    # client subcommand
    client_parser = subparsers.add_parser(
        "client",
        help="Fetch a certificate and private key from a running sslpv server.",
    )
    client_parser.add_argument(
        "--server",
        required=True,
        metavar="URL",
        help="Server base URL (must be https, e.g. https://example.com:1243).",
    )
    client_parser.add_argument(
        "--key",
        required=True,
        metavar="PATH",
        help="Path to a file containing the API key.",
    )
    client_parser.add_argument(
        "--cert",
        required=True,
        metavar="PATH",
        help="Destination path for the retrieved PEM certificate.",
    )
    client_parser.add_argument(
        "--privkey",
        required=True,
        metavar="PATH",
        help="Destination path for the retrieved PEM private key.",
    )
    client_parser.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        help="Disable TLS certificate verification (dangerous; not recommended).",
    )
    client_parser.add_argument(
        "--ca-cert",
        metavar="PATH",
        default=None,
        help="Path to a PEM CA bundle to use for TLS verification.",
    )
    client_parser.add_argument(
        "--pin-sha256",
        metavar="HEX",
        default=None,
        help="Expected SHA-256 hex fingerprint of the server leaf certificate.",
    )
    client_parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="Per-request timeout in seconds (default: 30.0).",
    )

    return parser


def _run_server_subcommand(args: argparse.Namespace) -> int:
    """Handle the 'server' subcommand.

    Args:
        args(argparse.Namespace): Parsed arguments containing config path.

    Return:
        exit_code(int): 0 on clean exit, 1 on error.
    """
    try:
        run_server(args.config)
        return 0
    except KeyboardInterrupt:
        print_message("Server stopped.", "fg:ansigreen")
        return 0
    except Exception as exc:
        print_message(f"Error: {exc}", "fg:ansired")
        return 1


def _run_client_subcommand(args: argparse.Namespace) -> int:
    """Handle the 'client' subcommand.

    Args:
        args(argparse.Namespace): Parsed arguments for the client.

    Return:
        exit_code(int): Exit code returned by run_client (0 = success).
    """
    return run_client(
        server=args.server,
        key_path=args.key,
        cert_path=args.cert,
        privkey_path=args.privkey,
        insecure=args.insecure,
        ca_cert=args.ca_cert,
        pin_sha256=args.pin_sha256,
        timeout=args.timeout,
    )


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point for sslpv.

    Parses arguments, sets up logging, and dispatches to the appropriate
    subcommand handler. Returns an integer exit code suitable for
    sys.exit().

    Args:
        argv(list[str], optional): Argument list; uses sys.argv[1:] when None.

    Return:
        exit_code(int): 0 on success, 1 on error, 2 when no subcommand given.
    """
    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print_message(f"sslpv {__version__}")
        return 0

    if args.subcommand is None:
        parser.print_help()
        return 2

    if args.subcommand == "server":
        return _run_server_subcommand(args)

    if args.subcommand == "client":
        return _run_client_subcommand(args)

    # Unreachable, but satisfies exhaustiveness.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
