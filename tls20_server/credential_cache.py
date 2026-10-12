"""Bounded credential representations; none of these helpers caches trust.

Only the caller's actual on-wire handshake frame belongs in its transcript.
Decompressed/reconstructed bodies are validation inputs, never extra messages.
Snapshots must be scoped to the current offer, credential type and peer policy.
"""

from __future__ import annotations

import hashlib
import hmac
import zlib

from .errors import ProtocolError
from .credential_limits import MAX_CERTIFICATES, MAX_CERT_DER, MAX_CERTIFICATE_BODY


MAX_CREDENTIAL_BODY = MAX_CERTIFICATE_BODY
COMPRESSION_ALGORITHMS = (1, 2, 3)


def _vector(value: bytes, width: int) -> bytes:
    if not isinstance(value, bytes) or len(value) >= 1 << (8 * width):
        raise ProtocolError("credential vector exceeds its wire length")
    return len(value).to_bytes(width, "big") + value


def _take(data: bytes, cursor: int, width: int, *, alert=40):
    if cursor + width > len(data):
        raise ProtocolError("truncated credential representation", alert=alert)
    size = int.from_bytes(data[cursor:cursor + width], "big")
    cursor += width
    if cursor + size > len(data):
        raise ProtocolError("truncated credential representation", alert=alert)
    return data[cursor:cursor + size], cursor + size


def cached_material(material, credential_type=0, *, max_size=MAX_CREDENTIAL_BODY):
    material = tuple(material)
    if credential_type not in (0, 2) or not material or len(material) > MAX_CERTIFICATES:
        raise ProtocolError("unsupported or empty cached credential material")
    if credential_type == 2 and len(material) != 1:
        raise ProtocolError("raw public key material must contain one entry")
    if any(not isinstance(entry, bytes) or not 1 <= len(entry) <= MAX_CERT_DER for entry in material):
        raise ProtocolError("cached credential entry length")
    size = 3 + sum(3 + len(entry) for entry in material)
    if size > max_size:
        raise ProtocolError("cached credential exceeds local budget")
    return _vector(b"".join(_vector(entry, 3) for entry in material), 3)


def material_hash(material, credential_type=0, *, max_size=MAX_CREDENTIAL_BODY):
    return hashlib.sha256(cached_material(material, credential_type, max_size=max_size)).digest()


def cached_certificate_body(material, extension_blocks, *, credential_type=0, context=b""):
    material, extension_blocks = tuple(material), tuple(extension_blocks)
    if len(material) != len(extension_blocks):
        raise ProtocolError("cached credential metadata count mismatch")
    body = (_vector(context, 1) + material_hash(material, credential_type)
            + _vector(b"".join(_vector(value, 2) for value in extension_blocks), 3))
    if len(body) > MAX_CREDENTIAL_BODY:
        raise ProtocolError("cached credential metadata exceeds local budget")
    return body


def resolve_cached_certificate(body, snapshots, *, credential_type=0, expected_context=b""):
    """Return exact offered material and CURRENT metadata; never authorize it.

    snapshots is a sequence of (credential_type, material) from this handshake's
    offer, not a mutable process-global cache. Equal digest with differing bytes
    or representations is rejected instead of choosing an arbitrary entry.
    """
    if len(body) > MAX_CREDENTIAL_BODY:
        raise ProtocolError("cached credential exceeds local budget")
    context, cursor = _take(body, 0, 1, alert=50)
    if cursor + 32 > len(body):
        raise ProtocolError("truncated cached credential hash", alert=50)
    wanted = body[cursor:cursor + 32]
    metadata, end = _take(body, cursor + 32, 3, alert=50)
    if end != len(body):
        raise ProtocolError("trailing cached credential data", alert=50)
    if context != expected_context:
        raise ProtocolError("cached credential context is invalid", alert=47)
    matched = None
    for kind, entries in snapshots:
        entries = tuple(entries)
        if hmac.compare_digest(material_hash(entries, kind), wanted):
            if kind != credential_type or matched is not None and matched != entries:
                raise ProtocolError("ambiguous cached credential material", alert=47)
            matched = entries
    if matched is None:
        raise ProtocolError("unoffered or missing cached credential material", alert=47)
    blocks, cursor = [], 0
    while cursor < len(metadata):
        value, cursor = _take(metadata, cursor, 2, alert=50)
        blocks.append(value)
        if len(blocks) > len(matched):
            raise ProtocolError("cached credential metadata count mismatch", alert=47)
    if len(blocks) != len(matched):
        raise ProtocolError("cached credential metadata count mismatch", alert=47)
    # Reconstructed Certificate-body size is bounded independently of reference.
    if 1 + len(context) + 3 + sum(5 + len(entry) + len(ext)
            for entry, ext in zip(matched, blocks)) > MAX_CREDENTIAL_BODY:
        raise ProtocolError("reconstructed credential exceeds local budget")
    return matched, tuple(blocks)


def request_template(extension_block: bytes):
    """Remove only fresh ff03; preserve every other Extension's original order."""
    cursor, seen, result = 0, set(), []
    while cursor < len(extension_block):
        if cursor + 4 > len(extension_block):
            raise ProtocolError("truncated certificate request extension")
        kind = int.from_bytes(extension_block[cursor:cursor + 2], "big")
        value, end = _take(extension_block, cursor + 2, 2)
        if kind in seen:
            raise ProtocolError("duplicate certificate request extension")
        if kind == 13:
            raise ProtocolError("signature_algorithms is not a TLS 2.0 request extension")
        seen.add(kind)
        if kind != 0xff03:
            result.append(extension_block[cursor:end])
        elif len(value) != 32:
            raise ProtocolError("invalid fresh client authentication share")
        cursor = end
    return _vector(b"".join(result), 2)


def request_template_hash(extension_block: bytes):
    return hashlib.sha256(request_template(extension_block)).digest()


def cached_request_body(context: bytes, extension_block: bytes, fresh_share: bytes):
    if len(fresh_share) != 32:
        raise ProtocolError("invalid fresh client authentication share")
    return _vector(context, 1) + request_template_hash(extension_block) + fresh_share


def resolve_cached_request(body: bytes, templates):
    context, cursor = _take(body, 0, 1, alert=50)
    if cursor + 64 != len(body):
        raise ProtocolError("invalid cached certificate request", alert=50)
    wanted, share = body[cursor:cursor + 32], body[cursor + 32:]
    matched = None
    for extension_block in templates:
        template = request_template(extension_block)
        if hmac.compare_digest(hashlib.sha256(template).digest(), wanted):
            if matched is not None and matched != template:
                raise ProtocolError("ambiguous cached request template", alert=47)
            matched = template
    if matched is None:
        raise ProtocolError("unoffered cached request template", alert=47)
    if len(matched) - 2 + 36 > 65535:
        raise ProtocolError("reconstructed certificate request exceeds wire length")
    # Reconstruct the extension block, with its fresh share LAST, only for the
    # normal request validator. The transcript continues to use the type-252 frame.
    return context, matched[2:] + b"\xff\x03\x00\x20" + share


def compress_certificate(body: bytes, algorithm: int):
    if not isinstance(body, bytes) or not 1 <= len(body) <= MAX_CREDENTIAL_BODY:
        raise ProtocolError("credential body exceeds compression budget")
    try:
        if algorithm == 1:
            data = zlib.compress(body)
        elif algorithm == 2:
            import brotli
            data = brotli.compress(body, quality=5)
        elif algorithm == 3:
            import zstandard
            data = zstandard.ZstdCompressor(level=3).compress(body)
        else:
            raise ProtocolError("unsupported certificate compression")
    except ImportError as exc:
        raise ProtocolError("certificate compression provider is unavailable") from exc
    if len(data) > MAX_CREDENTIAL_BODY:
        raise ProtocolError("compressed credential exceeds local budget")
    return algorithm.to_bytes(2, "big") + len(body).to_bytes(3, "big") + _vector(data, 3)


def _decompress_zstandard(data, declared, max_size):
    import zstandard

    # RFC 8478 permits concatenated and skippable frames. The streaming API
    # bounds output, but returns EOF for truncated input too, so first check
    # each frame's envelope. The provider still validates block contents,
    # dictionaries, content sizes and checksums during decompression below.
    source = memoryview(data)
    cursor, known_size = 0, 0
    window_limit = max(1024, max_size)
    while cursor < len(source):
        if len(source) - cursor < 4:
            raise ProtocolError("truncated zstandard frame", alert=42)
        magic = int.from_bytes(source[cursor:cursor + 4], "little")
        if 0x184D2A50 <= magic <= 0x184D2A5F:
            if len(source) - cursor < 8:
                raise ProtocolError("truncated zstandard skippable frame", alert=42)
            cursor += 8 + int.from_bytes(source[cursor + 4:cursor + 8], "little")
            if cursor > len(source):
                raise ProtocolError("truncated zstandard skippable frame", alert=42)
            continue
        if magic != 0xFD2FB528:
            raise ProtocolError("invalid or trailing zstandard frame", alert=42)
        parameters = zstandard.get_frame_parameters(source[cursor:])
        if parameters.window_size > window_limit:
            raise ProtocolError("zstandard window exceeds credential memory budget")
        if parameters.content_size != zstandard.CONTENTSIZE_UNKNOWN:
            known_size += parameters.content_size
            if known_size > declared:
                raise ProtocolError("zstandard frames exceed declared credential size", alert=42)
        cursor += zstandard.frame_header_size(source[cursor:])
        while True:
            if len(source) - cursor < 3:
                raise ProtocolError("truncated zstandard block header", alert=42)
            block = int.from_bytes(source[cursor:cursor + 3], "little")
            kind = (block >> 1) & 3
            if kind == 3:
                raise ProtocolError("reserved zstandard block type", alert=42)
            cursor += 3 + (1 if kind == 1 else block >> 3)
            if cursor > len(source):
                raise ProtocolError("truncated zstandard block", alert=42)
            if block & 1:
                break
        if parameters.has_checksum:
            cursor += 4
            if cursor > len(source):
                raise ProtocolError("truncated zstandard checksum", alert=42)

    # The pinned provider passes max_window_size directly to libzstd in bytes.
    # Keep an explicit header check as well as the decoder's allocation guard.
    decoder = zstandard.ZstdDecompressor(max_window_size=window_limit)
    result, used = bytearray(declared + 1), 0
    with decoder.stream_reader(source, read_across_frames=True) as reader:
        while used <= declared:
            count = reader.readinto(memoryview(result)[used:])
            if not count:
                break
            used += count
    if used != declared:
        raise ProtocolError("decompressed certificate length mismatch", alert=42)
    return bytes(result[:used])


def decompress_certificate(body: bytes, offered_algorithms, *, max_size=MAX_CREDENTIAL_BODY):
    if not isinstance(body, bytes) or len(body) < 8:
        raise ProtocolError("truncated compressed credential", alert=50)
    if len(body) > max_size + 8:
        raise ProtocolError("compressed credential exceeds local budget")
    algorithm = int.from_bytes(body[:2], "big")
    declared = int.from_bytes(body[2:5], "big")
    data, end = _take(body, 5, 3, alert=50)
    if end != len(body) or not data:
        raise ProtocolError("invalid compressed credential length", alert=50)
    if declared > max_size:
        raise ProtocolError("decompressed credential exceeds local budget")
    if algorithm not in offered_algorithms or algorithm not in COMPRESSION_ALGORITHMS:
        raise ProtocolError("unoffered certificate compression algorithm", alert=47)
    try:
        if algorithm == 1:
            decoder = zlib.decompressobj()
            result = decoder.decompress(data, declared + 1)
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ProtocolError("incomplete or trailing compressed certificate", alert=42)
        elif algorithm == 2:
            import brotli
            decoder = brotli.Decompressor()
            result = decoder.process(data, output_buffer_limit=declared + 1)
            while not decoder.is_finished() and not decoder.can_accept_more_data():
                if len(result) > declared:
                    raise ProtocolError("decompressed certificate exceeds declared length", alert=42)
                result += decoder.process(b"", output_buffer_limit=declared + 1 - len(result))
            if not decoder.is_finished():
                raise ProtocolError("incomplete compressed certificate", alert=42)
        else:
            result = _decompress_zstandard(data, declared, max_size)
        if len(result) != declared:
            raise ProtocolError("decompressed certificate length mismatch", alert=42)
        return result
    except ProtocolError:
        raise
    except Exception as exc:
        # Provider-specific malformed-input exceptions differ; never leak them or
        # retry another codec/credential representation after authentication fails.
        raise ProtocolError("certificate decompression failed", alert=42) from exc
