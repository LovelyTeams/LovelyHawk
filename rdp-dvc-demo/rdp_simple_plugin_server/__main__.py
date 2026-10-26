#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Entry point for the Simple DVC server.

Run with: python -m rdp_simple_plugin_server [OPTIONS]
Or after install: rdp-simple-dvc-server [OPTIONS]
"""

from __future__ import annotations

import argparse
import logging
import sys

# Handle both module execution (-m) and direct execution (PyInstaller)
try:
    from .simple_server import SimpleServer
except ImportError:
    from simple_server import SimpleServer


def _normalize_args(argv: list[str]) -> list[str]:
    normalized: list[str] = []
    for arg in argv:
        if arg.startswith(("/", "-")) and len(arg) > 1:
            key = arg[1:].lower()
            if key == "?":
                normalized.append("-h")
            else:
                normalized.append(f"-{key}")
        else:
            normalized.append(arg)
    return normalized


def main() -> int:
    """Parse arguments and run the server."""
    # Configure logging for the entire application
    # force=True ensures our config applies even if something logged earlier
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        force=True,
    )
    
    parser = argparse.ArgumentParser(
        prog="rdp-simple-dvc-server",
        description="Simple DVC Server - Python Implementation",
        epilog="""
This server runs inside an RDP session and communicates with the client
plugin via a Dynamic Virtual Channel (DVC). It sends periodic ping messages
and measures round-trip time (RTT).

The server must be started from within an RDP session where the client
plugin has registered the channel.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-f", "--filehandle",
        action="store_true",
        help="Use ReadFile/WriteFile OVERLAPPED mode instead of WTS API (synchronous)",
    )
    
    args = parser.parse_args(_normalize_args(sys.argv[1:]))
    
    # Enable debug for our packages by default
    logging.getLogger("rdp_simple_plugin_server").setLevel(logging.DEBUG)
    logging.getLogger("rdp_simple_plugin_protocol").setLevel(logging.DEBUG)
    
    return SimpleServer(use_file_handle=args.filehandle).run()


if __name__ == "__main__":
    sys.exit(main())
