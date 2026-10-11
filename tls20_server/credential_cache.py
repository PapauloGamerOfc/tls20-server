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


MAX_CREDENTIAL_BODY = 262144
COMPRESSION_ALGORITHMS = (1, 2, 3)


def _vector(value: bytes, width: int) -> bytes:
    if not isinstance(value, bytes) or len(value) >= 1 << (8 * width):
        raise ProtocolError("credential vector exceeds its wire length")
    return len(value).to_bytes(width, "big") + value


def _take(data: bytes, cursor: int, width: int):
    if cursor + width > len(data):
        raise ProtocolError("truncated credential representation")
    size = int.from_bytes(data[cursor:cursor + width], "big")
    cursor += width
    if cursor + size > len(data):
        raise ProtocolError("truncated credential representation")
    return data[cursor:cursor + size], cursor + size


def cached_material(material, credential_type=0, *, max_size=MAX_CREDENTIAL_BODY):
    material = tuple(material)
    if credential_type not in (0, 2) or not material or len(material) > 64:
        raise ProtocolError("unsupported or empty cached credential material")
    if credential_type == 2 and len(material) != 1:
        raise ProtocolError("raw public key material must contain one entry")
    if any(not isinstance(entry, bytes) or not entry for entry in material):
        raise ProtocolError("empty cached credential entry")
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
    context, cursor = _take(body, 0, 1)
    if context != expected_context or cursor + 32 > len(body):
        raise ProtocolError("cached credential context or hash is invalid")
    wanted = body[cursor:cursor + 32]
    metadata, end = _take(body, cursor + 32, 3)
    if end != len(body):
        raise ProtocolError("trailing cached credential data")
    matched = None
    for kind, entries in snapshots:
        entries = tuple(entries)
        if hmac.compare_digest(material_hash(entries, kind), wanted):
            if kind != credential_type or matched is not None and matched != entries:
                raise ProtocolError("ambiguous cached credential material")
            matched = entries
    if matched is None:
        raise ProtocolError("unoffered or missing cached credential material")
    blocks, cursor = [], 0
    while cursor < len(metadata):
        value, cursor = _take(metadata, cursor, 2)
        blocks.append(value)
        if len(blocks) > len(matched):
            raise ProtocolError("cached credential metadata count mismatch")
    if len(blocks) != len(matched):
        raise ProtocolError("cached credential metadata count mismatch")
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
    context, cursor = _take(body, 0, 1)
    if cursor + 64 != len(body):
        raise ProtocolError("invalid cached certificate request")
    wanted, share = body[cursor:cursor + 32], body[cursor + 32:]
    matched = None
    for extension_block in templates:
        template = request_template(extension_block)
        if hmac.compare_digest(hashlib.sha256(template).digest(), wanted):
            if matched is not None and matched != template:
                raise ProtocolError("ambiguous cached request template")
            matched = template
    if matched is None:
        raise ProtocolError("unoffered cached request template")
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


def decompress_certificate(body: bytes, offered_algorithms, *, max_size=MAX_CREDENTIAL_BODY):
    if not isinstance(body, bytes) or not 8 <= len(body) <= max_size + 8:
        raise ProtocolError("compressed credential exceeds local budget")
    algorithm = int.from_bytes(body[:2], "big")
    declared = int.from_bytes(body[2:5], "big")
    data, end = _take(body, 5, 3)
    if end != len(body) or not data or not 1 <= declared <= max_size:
        raise ProtocolError("invalid compressed credential length")
    if algorithm not in offered_algorithms or algorithm not in COMPRESSION_ALGORITHMS:
        raise ProtocolError("unoffered certificate compression algorithm")
    try:
        if algorithm == 1:
            decoder = zlib.decompressobj()
            result = decoder.decompress(data, declared + 1)
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ProtocolError("incomplete or trailing compressed certificate")
        elif algorithm == 2:
            import brotli
            decoder = brotli.Decompressor()
            result = decoder.process(data, output_buffer_limit=declared + 1)
            while not decoder.is_finished() and not decoder.can_accept_more_data():
                if len(result) > declared:
                    raise ProtocolError("decompressed certificate exceeds declared length")
                result += decoder.process(b"", output_buffer_limit=declared + 1 - len(result))
            if not decoder.is_finished():
                raise ProtocolError("incomplete compressed certificate")
        else:
            import zstandard
            frame_size = zstandard.frame_content_size(data)
            if frame_size not in (zstandard.CONTENTSIZE_UNKNOWN, zstandard.CONTENTSIZE_ERROR) and frame_size > declared:
                raise ProtocolError("zstandard frame exceeds declared credential size")
            decoder = zstandard.ZstdDecompressor(max_window_size=max(1024, (max_size + 1023) // 1024))
            result = decoder.decompress(data, max_output_size=declared, allow_extra_data=False)
        if len(result) != declared:
            raise ProtocolError("decompressed certificate length mismatch")
        return result
    except ProtocolError:
        raise
    except Exception as exc:
        # Provider-specific malformed-input exceptions differ; never leak them or
        # retry another codec/credential representation after authentication fails.
        raise ProtocolError("certificate decompression failed") from exc
