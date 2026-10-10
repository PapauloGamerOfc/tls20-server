"""HTTPPS test client; no automatic fallback, redirects, or insecure mode."""

import asyncio
from urllib.parse import quote, urlsplit

from .errors import ConfigurationError, ProtocolError
from .handshake import client_handshake
from .messages import validate_name


DEFAULT_PORT = 1021


def parse_url(url):
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "httpps" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("expected httpps://name[:port]/path without credentials")
        if parsed.fragment or any(ord(char) < 33 or ord(char) == 127 for char in url):
            raise ValueError("URL contains a fragment, whitespace or control characters")
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
        validate_name(hostname)
        port = DEFAULT_PORT if parsed.port is None else parsed.port
        if not 1 <= port <= 65535:
            raise ValueError("invalid port")
        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        if parsed.query:
            path += "?" + quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
        return hostname, port, path
    except (ValueError, UnicodeError) as exc:
        raise ConfigurationError("invalid HTTPPS URL") from exc


async def fetch(url, trust_roots, *, revocation_policy, output, connect_host=None,
                timeout=60, max_response_bytes=16777216):
    hostname, port, path = parse_url(url)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 3600:
        raise ConfigurationError("client timeout must be between 0 and 3600 seconds")
    if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or not 1 <= max_response_bytes <= 1073741824:
        raise ConfigurationError("invalid response limit")
    if revocation_policy != "lab-offline":
        raise ConfigurationError("the explicit lab-offline revocation policy is required")
    channel = None
    writer = None
    total = 0
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(connect_host or hostname, port, limit=32768)
            channel = await client_handshake(reader, writer, hostname, trust_roots,
                                             revocation_policy=revocation_policy,
                                             timeout=min(10, timeout))
            authority = hostname if port == DEFAULT_PORT else f"{hostname}:{port}"
            request = (f"GET {path} HTTP/1.1\r\nHost: {authority}\r\n"
                       "Connection: close\r\nUser-Agent: httpps-test-client/0.1\r\n\r\n").encode("ascii")
            await channel.send(request)
            while True:
                content = await channel.recv()
                if content is None:
                    return total
                total += len(content)
                if total > max_response_bytes:
                    raise ProtocolError("HTTP response exceeds local byte limit")
                output.write(content)
    finally:
        if channel is not None:
            await channel.close()
        elif writer is not None:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except (OSError, TimeoutError):
                writer.transport.abort()
            except asyncio.CancelledError:
                writer.transport.abort()
                raise
