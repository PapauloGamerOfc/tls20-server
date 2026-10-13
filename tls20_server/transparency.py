"""CT v1/v2 evidence verification with explicitly provisioned log parameters.

Valid SCT signatures are promises, NOT inclusion proofs, PKIX authorization or
automatic CT-policy compliance. No log discovered in peer input becomes trusted.
This module has no network fetching or implicit browser log-list side effects.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import time

from cryptography.hazmat.primitives import serialization

from .errors import ProtocolError
from .pki import _children, _element, _load_pkix_der, verify_public_signature


@dataclass(frozen=True)
class TrustedLog:
    log_id: bytes
    public_key: object
    signature_scheme: int = 0x0403
    hash_name: str = "sha256"
    valid_from_ms: int = 0
    valid_until_ms: int = (1 << 64) - 1
    maximum_merge_delay_seconds: int = 86400

    def __post_init__(self):
        if (not isinstance(self.log_id, bytes) or not self.log_id or self.hash_name not in ("sha256", "sha384", "sha512")
                or not 0 <= self.valid_from_ms < self.valid_until_ms < 1 << 64
                or self.maximum_merge_delay_seconds <= 0):
            raise ProtocolError("invalid explicit CT log parameters")


@dataclass(frozen=True)
class VerifiedSCT:
    log_id: bytes
    timestamp_ms: int
    signed_entry: bytes
    leaf_hash: bytes
    version: int
    included: bool = False


def _vec(data, width):
    if len(data) >= 1 << (8 * width):
        raise ProtocolError("CT vector exceeds wire length")
    return len(data).to_bytes(width, 'big') + data


def _take(data, offset, width):
    if offset + width > len(data):
        raise ProtocolError("truncated CT evidence")
    size = int.from_bytes(data[offset:offset + width], 'big')
    offset += width
    if offset + size > len(data):
        raise ProtocolError("truncated CT evidence vector")
    return data[offset:offset + size], offset + size


def _items(data):
    values, end = _take(data, 0, 2)
    if end != len(data) or len(data) > 65537:
        raise ProtocolError("invalid CT list framing")
    offset, result = 0, []
    while offset < len(values):
        value, offset = _take(values, offset, 2)
        if not value or len(result) >= 256:
            raise ProtocolError("empty CT item or local evidence budget exceeded")
        result.append(value)
    return result


def _extensions(data):
    offset, previous = 0, -1
    while offset < len(data):
        if offset + 4 > len(data):
            raise ProtocolError("truncated CT extension")
        kind = int.from_bytes(data[offset:offset + 2], 'big')
        _, offset = _take(data, offset + 2, 2)
        if kind <= previous:
            raise ProtocolError("CT extensions must be unique and ordered")
        previous = kind


def _der(tag, data):
    length = len(data)
    encoded = bytes((length,)) if length < 128 else bytes((0x80 + (length.bit_length() + 7) // 8,)) + length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes((tag,)) + encoded + data


# DER OBJECT IDENTIFIER values, not DER-encoded textual strings.
SCT_V1_OID = bytes.fromhex('2b06010401d679020402')
POISON_V1_OID = bytes.fromhex('2b06010401d679020403')
CT_V2_OID = bytes.fromhex('2b654b')


def precertificate_tbs(certificate, *, version):
    """Remove only the CT extensions required by the selected RFC format.

    Precertificate-signing intermediates require the caller's separately
    validated/reconstructed issuer binding; no issuer rewrite is guessed here.
    """
    removed = {SCT_V1_OID, POISON_V1_OID} if version == 1 else {SCT_V1_OID, CT_V2_OID}
    _, data, _, _ = _element(certificate.tbs_certificate_bytes)
    output = []
    for tag, content, raw in _children(data):
        if tag != 0xa3:
            output.append(raw)
            continue
        seq, extensions, end, _ = _element(content)
        if seq != 0x30 or end != len(content):
            raise ProtocolError("invalid CT certificate extensions")
        kept = []
        for extension_tag, extension_body, extension_raw in _children(extensions):
            fields = _children(extension_body)
            if extension_tag != 0x30 or not fields or fields[0][0] != 6:
                raise ProtocolError("invalid CT certificate extension")
            if fields[0][1] not in removed:
                kept.append(extension_raw)
        if kept:
            output.append(_der(0xa3, _der(0x30, b''.join(kept))))
    return _der(0x30, b''.join(output))


def embedded_transparency(certificate):
    _, data, _, _ = _element(certificate.tbs_certificate_bytes)
    result = {}
    for tag, content, _ in _children(data):
        if tag != 0xa3:
            continue
        _, extension_body, _, _ = _element(content)
        for _, fields, _ in _children(extension_body):
            parsed = _children(fields)
            oid = parsed[0][1]
            if oid not in (SCT_V1_OID, CT_V2_OID):
                continue
            if parsed[-1][0] != 4:
                raise ProtocolError("invalid embedded CT evidence")
            nested_tag, value, end, _ = _element(parsed[-1][1])
            if nested_tag != 4 or end != len(parsed[-1][1]):
                raise ProtocolError("CT X.509 evidence requires a DER OCTET STRING")
            result[18 if oid == SCT_V1_OID else 52] = value
    return result


def _timestamp(log, timestamp, now_ms):
    if not log.valid_from_ms <= timestamp <= min(log.valid_until_ms, now_ms):
        raise ProtocolError("CT timestamp is outside the authorized log interval")


def validate_sct_v1_list(data, certificate_der, trusted_logs, *, issuer_der=None,
                        precertificate=False, now_ms=None):
    certificate = _load_pkix_der(certificate_der)
    moment = int(time.time() * 1000) if now_ms is None else now_ms
    verified = []
    for value in _items(data):
        if value[0] != 0:
            continue  # Independently length-framed future version.
        if len(value) < 47:
            raise ProtocolError("truncated v1 SCT")
        log_id, timestamp = value[1:33], int.from_bytes(value[33:41], 'big')
        extensions, offset = _take(value, 41, 2)
        if offset + 4 > len(value):
            raise ProtocolError("truncated v1 SCT signature")
        algorithm = value[offset:offset + 2]
        signature, end = _take(value, offset + 2, 2)
        if end != len(value) or not signature:
            raise ProtocolError("invalid v1 SCT signature framing")
        log = trusted_logs.get(log_id)
        if log is None:
            continue
        spki = log.public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if log_id != log.log_id or not hmac.compare_digest(hashlib.sha256(spki).digest(), log_id):
            raise ProtocolError("v1 CT log ID is not its provisioned SPKI hash")
        scheme = {b'\x04\x03': 0x0403, b'\x04\x01': 0x0401}.get(algorithm)
        if scheme is None or scheme != log.signature_scheme:
            raise ProtocolError("v1 SCT signature disagrees with trusted log parameters")
        _timestamp(log, timestamp, moment)
        if precertificate:
            if issuer_der is None:
                raise ProtocolError("precertificate SCT needs its validated issuer")
            issuer = _load_pkix_der(issuer_der)
            spki = issuer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            entry = b'\x00\x01' + hashlib.sha256(spki).digest() + _vec(precertificate_tbs(certificate, version=1), 3)
        else:
            entry = b'\x00\x00' + _vec(certificate_der, 3)
        signed = b'\x00\x00' + timestamp.to_bytes(8, 'big') + entry + _vec(extensions, 2)
        verify_public_signature(log.public_key, scheme, signature, signed)
        verified.append(VerifiedSCT(log_id, timestamp, signed, hashlib.sha256(b'\x00' + signed).digest(), 1))
    return tuple(verified)


def verify_inclusion(leaf_hash, leaf_index, tree_size, path, root_hash, *, hash_name='sha256'):
    size = hashlib.new(hash_name).digest_size
    if (not 0 <= leaf_index < tree_size < 1 << 64 or len(leaf_hash) != size or len(root_hash) != size
            or len(path) > 64 or any(len(item) != size for item in path)):
        raise ProtocolError("invalid CT inclusion proof parameters")
    index, last, value = leaf_index, tree_size - 1, leaf_hash
    for sibling in path:
        if last == 0:
            raise ProtocolError("CT inclusion proof has excess nodes")
        if index & 1 or index == last:
            value = hashlib.new(hash_name, b'\x01' + sibling + value).digest()
            while index and not index & 1:
                index >>= 1
                last >>= 1
        else:
            value = hashlib.new(hash_name, b'\x01' + value + sibling).digest()
        index >>= 1
        last >>= 1
    if last or not hmac.compare_digest(value, root_hash):
        raise ProtocolError("CT inclusion proof does not match the signed root")
    return True


def verify_consistency(old_size, new_size, old_root, new_root, path, *, hash_name='sha256'):
    """Verify append-only consistency against a PREVIOUSLY trusted tree root."""
    width = hashlib.new(hash_name).digest_size
    if (not 0 <= old_size <= new_size < 1 << 64 or len(old_root) != width or len(new_root) != width
            or len(path) > 64 or any(len(value) != width for value in path)):
        raise ProtocolError("invalid CT consistency proof parameters")
    if old_size == 0:
        if path or old_root != hashlib.new(hash_name, b'').digest():
            raise ProtocolError("invalid empty CT tree consistency proof")
        return True
    if old_size == new_size:
        if path or not hmac.compare_digest(old_root, new_root):
            raise ProtocolError("inconsistent CT roots for identical tree sizes")
        return True
    first, second = old_size - 1, new_size - 1
    while first & 1:
        first >>= 1
        second >>= 1
    nodes = iter(path)
    if first == 0:
        old_hash = new_hash = old_root
    else:
        try:
            old_hash = new_hash = next(nodes)
        except StopIteration as exc:
            raise ProtocolError("CT consistency proof is incomplete") from exc
    for node in nodes:
        if second == 0:
            raise ProtocolError("CT consistency proof has excess nodes")
        if first & 1 or first == second:
            old_hash = hashlib.new(hash_name, b'\x01' + node + old_hash).digest()
            new_hash = hashlib.new(hash_name, b'\x01' + node + new_hash).digest()
            while first and not first & 1:
                first >>= 1
                second >>= 1
        else:
            new_hash = hashlib.new(hash_name, b'\x01' + new_hash + node).digest()
        first >>= 1
        second >>= 1
    if second or not hmac.compare_digest(old_hash, old_root) or not hmac.compare_digest(new_hash, new_root):
        raise ProtocolError("CT append-only consistency proof failed")
    return True


def _node_path(raw, hash_size):
    result, offset = [], 0
    while offset < len(raw):
        node, offset = _take(raw, offset, 1)
        if len(node) != hash_size or len(result) >= 64:
            raise ProtocolError("invalid or excessive CT Merkle path")
        result.append(node)
    return tuple(result)


def validate_ct_v2_list(data, certificate_der, issuer_der, trusted_logs, *, now_ms=None,
                         require_inclusion=False, trusted_tree_heads=None):
    certificate, issuer = _load_pkix_der(certificate_der), _load_pkix_der(issuer_der)
    moment = int(time.time() * 1000) if now_ms is None else now_ms
    verified, heads, proofs, consistency = [], {}, [], []
    saw_sct = False
    for value in _items(data):
        if len(value) < 2:
            raise ProtocolError("truncated CT v2 TransItem")
        kind = int.from_bytes(value[:2], 'big')
        if kind not in (0x0102, 0x0103, 0x0104, 0x0105, 0x0106):
            continue
        saw_sct |= kind in (0x0102, 0x0103)
        log_id, offset = _take(value, 2, 1)
        if not 2 <= len(log_id) <= 127:
            raise ProtocolError("invalid CT v2 log identifier")
        log = trusted_logs.get(log_id)
        if log is None:
            continue
        if log_id != log.log_id:
            raise ProtocolError("CT log parameter identity mismatch")
        hash_size = hashlib.new(log.hash_name).digest_size
        if kind in (0x0102, 0x0103):
            if offset + 8 > len(value):
                raise ProtocolError("truncated v2 SCT timestamp")
            timestamp = int.from_bytes(value[offset:offset + 8], 'big')
            extensions, offset = _take(value, offset + 8, 2)
            _extensions(extensions)
            signature, end = _take(value, offset, 2)
            if end != len(value) or not signature:
                raise ProtocolError("invalid v2 SCT signature framing")
            _timestamp(log, timestamp, moment)
            issuer_spki = issuer.public_key().public_bytes(serialization.Encoding.DER,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo)
            tbs = certificate.tbs_certificate_bytes if kind == 0x0102 else precertificate_tbs(certificate, version=2)
            signed = ((kind - 2).to_bytes(2, 'big') + timestamp.to_bytes(8, 'big')
                + _vec(hashlib.new(log.hash_name, issuer_spki).digest(), 1) + _vec(tbs, 3) + _vec(extensions, 2))
            verify_public_signature(log.public_key, log.signature_scheme, signature, signed)
            verified.append(VerifiedSCT(log_id, timestamp, signed,
                             hashlib.new(log.hash_name, b'\x00' + signed).digest(), 2))
        elif kind == 0x0104:
            start = offset
            if offset + 16 > len(value):
                raise ProtocolError("truncated CT tree head")
            timestamp, size = int.from_bytes(value[offset:offset + 8], 'big'), int.from_bytes(value[offset + 8:offset + 16], 'big')
            root, offset = _take(value, offset + 16, 1)
            extensions, offset = _take(value, offset, 2)
            _extensions(extensions)
            signature, end = _take(value, offset, 2)
            if end != len(value) or len(root) != hash_size or not signature:
                raise ProtocolError("invalid CT tree head signature framing")
            _timestamp(log, timestamp, moment)
            verify_public_signature(log.public_key, log.signature_scheme, signature, value[start:offset])
            key = (log_id, size)
            if key in heads and heads[key][1] != root:
                raise ProtocolError("conflicting signed roots for the same CT tree size")
            # A TransItemList has no chronological ordering requirement. Keep
            # the freshest signed head for this same root, not the last item.
            if key not in heads or heads[key][0] < timestamp:
                heads[key] = (timestamp, root)
        elif kind == 0x0106:
            if offset + 16 > len(value):
                raise ProtocolError("truncated CT inclusion proof")
            size, index = int.from_bytes(value[offset:offset + 8], 'big'), int.from_bytes(value[offset + 8:offset + 16], 'big')
            path, end = _take(value, offset + 16, 2)
            if end != len(value):
                raise ProtocolError("trailing CT inclusion proof data")
            proofs.append((log_id, size, index, _node_path(path, hash_size)))
        else:
            # A consistency proof requires a separately retained trusted STH.
            # It is not treated as an inclusion proof or an authentication vote.
            if offset + 16 > len(value):
                raise ProtocolError("truncated CT consistency proof")
            old_size = int.from_bytes(value[offset:offset + 8], 'big')
            new_size = int.from_bytes(value[offset + 8:offset + 16], 'big')
            path, end = _take(value, offset + 16, 2)
            if end != len(value):
                raise ProtocolError("trailing CT consistency proof data")
            consistency.append((log_id, old_size, new_size, _node_path(path, hash_size)))
    if not saw_sct:
        raise ProtocolError("CT v2 evidence list does not contain an SCT")
    if trusted_tree_heads:
        for (log_id, size), head in heads.items():
            previous = trusted_tree_heads.get(log_id)
            if previous is None:
                continue
            old_size, old_timestamp, old_root = previous
            if size < old_size or head[0] < old_timestamp:
                raise ProtocolError("CT signed tree head rolled back trusted state")
            candidates = [path for identity, first, second, path in consistency
                          if identity == log_id and first == old_size and second == size]
            if size == old_size or old_size == 0:
                candidates.append(())
            verified_consistency = False
            for path in candidates:
                try:
                    verify_consistency(old_size, size, old_root, head[1], path,
                                       hash_name=trusted_logs[log_id].hash_name)
                except ProtocolError:
                    continue
                verified_consistency = True
                break
            if not verified_consistency:
                raise ProtocolError("CT head lacks consistency with the configured trusted state")
    result = []
    for item in verified:
        log = trusted_logs[item.log_id]
        included = False
        for log_id, size, index, path in proofs:
            head = heads.get((log_id, size))
            if log_id != item.log_id or head is None or head[0] < item.timestamp_ms:
                continue
            try:
                verify_inclusion(item.leaf_hash, index, size, path, head[1], hash_name=log.hash_name)
            except ProtocolError:
                continue  # A proof may refer to another independently valid SCT.
            included = True
            break
        if require_inclusion and not included:
            raise ProtocolError("required CT inclusion evidence is absent or invalid")
        result.append(VerifiedSCT(item.log_id, item.timestamp_ms, item.signed_entry, item.leaf_hash, 2, included))
    return tuple(result)
