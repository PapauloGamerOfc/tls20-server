"""HTTPPS test client; no automatic fallback, redirects, or insecure mode."""

import asyncio
from urllib.parse import quote, urlsplit

from .constants import DEFAULT_PORT
from .errors import ConfigurationError, ProtocolError
from .handshake import client_handshake
from .messages import validate_name


class _EarlyResponseStatus:
    """Inspect the final HTTP status, including bounded informational responses."""

    def __init__(self):
        self.buffer = bytearray()
        self.offset = 0
        self.informational = 0

    def feed(self, content):
        self.buffer.extend(content)
        while True:
            end = self.buffer.find(b"\r\n", self.offset)
            if end < 0:
                if len(self.buffer) - self.offset > 8192:
                    raise ProtocolError("HTTP response status line exceeds local limit")
                return None
            if end - self.offset > 8192:
                raise ProtocolError("HTTP response status line exceeds local limit")
            status = bytes(self.buffer[self.offset:end]).split(b" ", 2)
            if (len(status) < 2 or status[0] not in (b"HTTP/1.1", b"HTTP/1.0")
                    or len(status[1]) != 3 or not status[1].isdigit()):
                raise ProtocolError("invalid HTTP response status")
            code = int(status[1])
            if not 100 <= code < 200 or code == 101:
                return code == 425
            headers_end = self.buffer.find(b"\r\n\r\n", self.offset)
            if headers_end < 0:
                if len(self.buffer) > 65536:
                    raise ProtocolError("HTTP informational responses exceed local limit")
                return None
            self.offset = headers_end + 4
            self.informational += 1
            if self.offset > 65536 or self.informational > 16:
                raise ProtocolError("HTTP informational responses exceed local limit")


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
                timeout=60, max_response_bytes=16777216, ticket_cache=None,
                use_early_data=False):
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
    retry_without_early = False
    response_status = _EarlyResponseStatus()
    deadline = asyncio.get_running_loop().time() + timeout
    authority = hostname if port == DEFAULT_PORT else f"{hostname}:{port}"
    request = (f"GET {path} HTTP/1.1\r\nHost: {authority}\r\n"
               "Connection: close\r\nUser-Agent: httpps-test-client/0.1\r\n\r\n").encode("ascii")
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(connect_host or hostname, port, limit=32768)
            channel = await client_handshake(reader, writer, hostname, trust_roots,
                                             revocation_policy=revocation_policy,
                                             timeout=min(10, timeout),
                                             ticket_cache=ticket_cache,
                                             cache_context=f"{hostname}:{port}".encode("ascii"),
                                             early_data=request if use_early_data else b"")
            if not channel.early_data_accepted:
                await channel.send(request)
            inspect_status = use_early_data and channel.early_data_accepted
            while True:
                content = await channel.recv()
                if content is None:
                    if inspect_status:
                        raise ProtocolError("HTTP response ended before its final status")
                    return total
                total += len(content)
                if total > max_response_bytes:
                    raise ProtocolError("HTTP response exceeds local byte limit")
                if inspect_status:
                    retry = response_status.feed(content)
                    if retry is None:
                        continue
                    if retry:
                        retry_without_early = True
                        break
                    output.write(response_status.buffer)
                    response_status.buffer.clear()
                    inspect_status = False
                else:
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
    if retry_without_early:
        # Exactly one HTTP-layer retry, only for this client's bodyless GET and
        # only if TLS accepted early data. Authentication failures never retry.
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("HTTPPS request deadline expired before retry")
        return await fetch(url, trust_roots, revocation_policy=revocation_policy,
                           output=output, connect_host=connect_host, timeout=remaining,
                           max_response_bytes=max_response_bytes, ticket_cache=ticket_cache,
                           use_early_data=False)
