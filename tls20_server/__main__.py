"""Command line entry point."""

import argparse
import asyncio
import logging
from pathlib import Path
import sys

from . import __version__
from .client import fetch
from .config import load_config
from .constants import DEFAULT_PORT
from .errors import ConfigurationError, ProtocolError
from .lab import create_lab
from .pki import load_credentials, load_trust_roots
from .server import start_server
from .tickets import TicketCache


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
    password = commands.add_parser("password-record", help="create one salted password verifier from private UTF-8 files")
    password.add_argument("--username-file", type=Path, required=True)
    password.add_argument("--password-file", type=Path, required=True)
    password.add_argument("--output", type=Path, required=True)
    client = commands.add_parser("get", help="print the raw HTTP response from an HTTPPS endpoint")
    client.add_argument("url")
    trust = client.add_mutually_exclusive_group(required=True)
    trust.add_argument("--ca", type=Path)
    trust.add_argument("--profile", type=Path, help="explicit role/service-bound client profile TOML")
    client.add_argument("--revocation-policy", choices=["lab-offline", "offline"],
                        help="explicit offline trust: restricted lab chain or general PKIX; neither checks revocation")
    client.add_argument("--connect-host", help="transport destination override; certificate identity still comes from the URL")
    client.add_argument("--timeout", type=float, default=60)
    client.add_argument("--max-response-bytes", type=int, default=16777216)
    client.add_argument("--repeat", type=int, default=1,
                        help="repeat GET on fresh connections, sharing an in-memory session cache")
    client.add_argument("--early-data", action="store_true",
                        help="opt into replayable 0-RTT GET after the first authenticated connection")
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


async def fetch_repeated(args, roots, profile=None):
    if not 1 <= args.repeat <= 1000:
        raise ConfigurationError("--repeat must be between 1 and 1000")
    cache = TicketCache()
    for _ in range(args.repeat):
        await fetch(args.url, roots, revocation_policy=args.revocation_policy,
                    output=sys.stdout.buffer, connect_host=args.connect_host,
                    timeout=args.timeout, max_response_bytes=args.max_response_bytes,
                    ticket_cache=cache, use_early_data=args.early_data, profile=profile)


def main(argv=None):
    argument_parser = parser()
    args = argument_parser.parse_args(argv)
    if args.command == "get" and args.ca is not None and args.revocation_policy is None:
        argument_parser.error("--revocation-policy is required with --ca")
    if args.command == "get" and args.profile is not None and args.revocation_policy is not None:
        argument_parser.error("--profile specifies its own revocation policy")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        if args.command == "lab-init":
            create_lab(args.directory, args.name)
            # The generator refuses existing directories. This file is new too.
            config = ("# Local experimental setup; the CA is not installed in the OS.\n"
                      f'listen = "127.0.0.1:{DEFAULT_PORT}"\nupstream = "127.0.0.1:8080"\n'
                      f'server_name = "{args.name}"\n'
                      'certificate_chain = "fullchain.pem"\nprivate_key = "server.key"\n')
            with (args.directory / "server.toml").open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(config)
            print(f"Created lab credentials and configuration in {args.directory}.")
            print("Trust ca.pem explicitly in the test client. Do not deploy these as a public PKI.")
        elif args.command == "check-config":
            config = load_config(args.config)
            if config.profile_file is None:
                load_credentials(config.certificate_chain, config.private_key, config.server_name)
            else:
                from .profiles import load_profile
                profile = load_profile(config.profile_file, role="server", service=config.server_name,
                    port=config.listen.port, protocol=config.upstream_protocol.encode("ascii"))
                profile.close()
            print("Configuration and server credentials validated; no listener opened.")
        elif args.command == "serve":
            asyncio.run(serve(load_config(args.config)))
        elif args.command == "password-record":
            from .profiles import create_password_record
            create_password_record(args.username_file, args.password_file, args.output)
            print("Created one salted password record; protect its file as a secret.")
        elif args.command == "get":
            if args.profile is not None:
                from .client import parse_url
                from .profiles import load_profile
                name, port, _ = parse_url(args.url)
                profile = load_profile(args.profile, role="client", service=name, port=port)
                try:
                    asyncio.run(fetch_repeated(args, profile.roots, profile))
                finally:
                    profile.close()
            else:
                roots = load_trust_roots(args.ca, general_pkix=args.revocation_policy == "offline")
                asyncio.run(fetch_repeated(args, roots))
        return 0
    except KeyboardInterrupt:
        return 130
    except (ConfigurationError, ProtocolError, OSError, TimeoutError, ValueError) as exc:
        # Never print a traceback or serialized protocol data during routine use.
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
