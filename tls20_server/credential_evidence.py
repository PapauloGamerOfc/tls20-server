"""Explicit current OCSP/CT policy adapter for CredentialPolicy.

Trust roots and trusted log keys are provided by the application. Peer URLs are
never fetched. SCT signatures do not silently turn into proof of log inclusion.
"""

from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp

from .credential_profiles import validate_ocsp_response
from .errors import ProtocolError
from .pki import _children, _element
from .status_request import parse_status_request, response_matches_request
from .tls_features import validate_feature_path
from .transparency import (CT_V2_OID, SCT_V1_OID, embedded_transparency,
                           validate_ct_v2_list, validate_sct_v1_list, _items, _vec)


def _status_response(value):
    if len(value) < 4 or value[0] != 1 or int.from_bytes(value[1:4], 'big') != len(value) - 4:
        raise ProtocolError("malformed TLS certificate status response")
    return value[4:]


def _ocsp_transparency(response_der, certificate, issuer):
    """Extract ONLY the matching SingleResponse after OCSP was authenticated."""
    response = ocsp.load_der_ocsp_response(response_der)
    _, outer, _, _ = _element(response_der)
    fields = _children(outer)
    if len(fields) != 2 or fields[1][0] != 0xa0:
        raise ProtocolError("invalid authenticated OCSP envelope")
    _, response_bytes, _, _ = _element(fields[1][1])
    response_fields = _children(response_bytes)
    if len(response_fields) != 2 or response_fields[-1][0] != 4:
        raise ProtocolError("invalid authenticated OCSP payload")
    _, basic, _, _ = _element(response_fields[-1][1])
    tbs = _children(_children(basic)[0][1])
    start = 1 if tbs[0][0] == 0xa0 else 0
    if len(tbs) <= start + 2 or tbs[start + 2][0] != 0x30:
        raise ProtocolError("invalid authenticated OCSP response list")
    singles = _children(tbs[start + 2][1])
    parsed_responses = tuple(response.responses)
    if len(singles) != len(parsed_responses):
        raise ProtocolError("inconsistent OCSP response decoding")
    result = {}
    for (_, single, _), parsed in zip(singles, parsed_responses):
        reference = ocsp.OCSPRequestBuilder().add_certificate(certificate, issuer, parsed.hash_algorithm).build()
        if (parsed.serial_number, parsed.issuer_name_hash, parsed.issuer_key_hash) != (
                reference.serial_number, reference.issuer_name_hash, reference.issuer_key_hash):
            continue
        for tag, payload, _ in _children(single):
            if tag != 0xa1:
                continue
            _, extensions, _, _ = _element(payload)
            for _, extension, _ in _children(extensions):
                parts = _children(extension)
                if parts[0][0] != 6 or parts[-1][0] != 4:
                    raise ProtocolError("invalid OCSP CT extension")
                kind = {SCT_V1_OID:18, CT_V2_OID:52}.get(parts[0][1])
                if kind is None:
                    continue
                wrapped_tag, value, end, _ = _element(parts[-1][1])
                if wrapped_tag != 4 or end != len(parts[-1][1]) or kind in result:
                    raise ProtocolError("invalid or duplicate OCSP CT extension")
                result[kind] = value
    return result


@dataclass(frozen=True)
class CredentialEvidencePolicy:
    require_ocsp: bool = False
    enforce_tls_feature: bool = True
    expected_ocsp_nonce: bytes | None = None
    ocsp_max_age_seconds: int = 86400
    trusted_logs_v1: object = field(default_factory=dict)
    trusted_logs_v2: object = field(default_factory=dict)
    minimum_ct_v1_logs: int = 0
    minimum_ct_v2_logs: int = 0
    require_ct_v2_inclusion: bool = False
    trusted_tree_heads: object = None
    offered_extensions: tuple = ()
    ocsp_request: bytes | None = None
    negotiated_extensions: tuple = ()

    def __call__(self, path, role, evidence, moment):
        if not path or len(evidence) > len(path):
            raise ProtocolError("credential evidence is not bound to the current path")
        if role != 'server' and (self.minimum_ct_v1_logs or self.minimum_ct_v2_logs):
            raise ProtocolError("CT client identity policy is not defined by this profile")
        extensions = tuple(dict(item) for item in evidence)
        leaf = extensions[0] if extensions else {}
        must_staple = False
        required = frozenset()
        if self.enforce_tls_feature:
            features = validate_feature_path(path)
            required = features.intersection(self.offered_extensions)
            if required - set(leaf) - set(self.negotiated_extensions):
                raise ProtocolError("an offered mandatory TLS Feature was not satisfied")
            must_staple = 5 in required
        if (self.require_ocsp or must_staple) and 5 not in leaf:
            raise ProtocolError("required current OCSP staple is absent")
        sources = [(embedded_transparency(path[0]), True)]
        for index, values in enumerate(extensions):
            if 5 not in values:
                continue
            if index + 1 >= len(path):
                raise ProtocolError("OCSP staple issuer is not available in the validated path")
            response = _status_response(values[5])
            if self.ocsp_request is not None and not response_matches_request(response, parse_status_request(self.ocsp_request)):
                raise ProtocolError("OCSP response does not satisfy the actual request")
            validate_ocsp_response(response, path[index], path[index + 1], now=moment,
                expected_nonce=self.expected_ocsp_nonce, max_age_seconds=self.ocsp_max_age_seconds)
            if index == 0:
                sources.append((_ocsp_transparency(response, path[0], path[1]), False))
        sources.append((leaf, False))
        if self.minimum_ct_v2_logs and not {5, 52}.issubset(self.offered_extensions):
            raise ProtocolError("CT v2 compliance requires both status_request and transparency_info offers")
        if (self.minimum_ct_v1_logs < 0 or self.minimum_ct_v2_logs < 0
                or self.minimum_ct_v1_logs and not self.trusted_logs_v1
                or self.minimum_ct_v2_logs and not self.trusted_logs_v2):
            raise ProtocolError("invalid explicit CT evidence policy")
        v1, v2, tls_v1, tls_v2 = set(), set(), set(), set()
        encoded = [cert.public_bytes(serialization.Encoding.DER) for cert in path]
        for source, embedded in sources:
            if 18 in source and self.trusted_logs_v1:
                # Embedded SCTs are always for precertificates. TLS/OCSP SCTs
                # may attest either form; the log signature decides, not parsing.
                modes = (True,) if embedded else (False, True)
                for item in _items(source[18]):
                    framed = _vec(_vec(item, 2), 2)
                    for mode in modes:
                        try:
                            result = validate_sct_v1_list(framed, encoded[0], self.trusted_logs_v1,
                                issuer_der=encoded[1] if len(encoded) > 1 else None,
                                precertificate=mode, now_ms=int(moment.timestamp() * 1000))
                        except ProtocolError:
                            continue  # Invalid/untrusted SCTs contribute no policy vote.
                        v1.update(item.log_id for item in result)
                        if source is leaf:
                            tls_v1.update(item.log_id for item in result)
                        break
            if 52 in source and self.trusted_logs_v2:
                if len(encoded) < 2:
                    raise ProtocolError("CT v2 requires the validated certificate issuer")
                result = validate_ct_v2_list(source[52], encoded[0], encoded[1], self.trusted_logs_v2,
                    now_ms=int(moment.timestamp() * 1000), require_inclusion=self.require_ct_v2_inclusion,
                    trusted_tree_heads=self.trusted_tree_heads)
                v2.update(item.log_id for item in result)
                if source is leaf:
                    tls_v2.update(item.log_id for item in result)
        if (18 in required and not tls_v1) or (52 in required and not tls_v2):
            raise ProtocolError("mandatory TLS transparency extension has no verified log evidence")
        if len(v1) < self.minimum_ct_v1_logs or len(v2) < self.minimum_ct_v2_logs:
            raise ProtocolError("current CT evidence does not satisfy the configured log policy")
        return True
