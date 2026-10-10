"""Command line entry point."""

import argparse
import asyncio
import logging
from pathlib import Path
import sys

from . import __version__
from .client import fetch
from .config import load_config
from .errors import ConfigurationError, ProtocolError
from .lab import create_lab
from .pki import load_credentials, load_trust_roots
from .server import start_server


def parser():
    result = argparse.ArgumentParser(description="Independent experimental HTTPPS proxy; not standard TLS.")
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("serve", "check-config"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, default=Path("server.toml"))
    lab = commands.add_parser("lab-init", help="create fresh, isolated test credentials; never installs a CA")
    lab.add_argument("--directory", type=Path, required=True)
    lab.add_argument("--name", default="localhost")
    client = commands.add_parser("get", help="print the raw HTTP response from an HTTPPS endpoint")
    client.add_argument("url")
    client.add_argument("--ca", type=Path, required=True)
    client.add_argument("--revocation-policy", choices=["lab-offline"], required=True,
                        help="acknowledge lab-only offline certificates without revocation checking")
    client.add_argument("--connect-host", help="transport destination override; certificate identity still comes from the URL")
    client.add_argument("--timeout", type=float, default=60)
    client.add_argument("--max-response-bytes", type=int, default=16777216)
    return result


async def serve(config):
    running = await start_server(config)
    addresses = ", ".join(str(sock.getsockname()) for sock in running.server.sockets)
    logging.info("Experimental HTTPPS listening on %s; upstream %s:%s", addresses,
                 config.upstream.host, config.upstream.port)
    try:
        await running.server.serve_forever()
    finally:
        await running.close()


def main(argv=None):
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        if args.command == "lab-init":
            create_lab(args.directory, args.name)
            # The generator refuses existing directories. This file is new too.
            config = ("# Local experimental setup; the CA is not installed in the OS.\n"
                      'listen = "127.0.0.1:1021"\nupstream = "127.0.0.1:8080"\n'
                      f'server_name = "{args.name}"\n'
                      'certificate_chain = "fullchain.pem"\nprivate_key = "server.key"\n')
            with (args.directory / "server.toml").open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(config)
            print(f"Created lab credentials and configuration in {args.directory}.")
            print("Trust ca.pem explicitly in the test client. Do not deploy these as a public PKI.")
        elif args.command == "check-config":
            config = load_config(args.config)
            load_credentials(config.certificate_chain, config.private_key, config.server_name)
            print("Configuration and server credentials validated; no listener opened.")
        elif args.command == "serve":
            asyncio.run(serve(load_config(args.config)))
        elif args.command == "get":
            roots = load_trust_roots(args.ca)
            asyncio.run(fetch(args.url, roots, revocation_policy=args.revocation_policy,
                              output=sys.stdout.buffer, connect_host=args.connect_host,
                              timeout=args.timeout, max_response_bytes=args.max_response_bytes))
        return 0
    except KeyboardInterrupt:
        return 130
    except (ConfigurationError, ProtocolError, OSError, TimeoutError, ValueError) as exc:
        # Never print a traceback or serialized protocol data during routine use.
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
