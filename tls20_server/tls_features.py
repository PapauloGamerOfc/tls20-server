"""RFC7633 feature values and issuer constraints on an already verified path."""

from cryptography.hazmat.primitives import serialization

from .credential_selection import _single_der, _der
from .errors import ProtocolError
from .pki import _children, _element

_OID = bytes.fromhex("2b06010505070118")


def certificate_features(cert):
    # Decode the registry-valued INTEGERs, not cryptography's closed two-value
    # TLSFeature enum: an unknown, unoffered registry value is not an error.
    _, body, _, _ = _element(cert.public_bytes(serialization.Encoding.DER))
    tbs = _children(body)[0][1]
    found = None
    for tag, value, _ in _children(tbs):
        if tag != 0xa3:
            continue
        for _, encoded, _ in _children(_single_der(value, 48)):
            parts = _children(encoded)
            if not parts or parts[0][0] != 6 or parts[0][1] != _OID:
                continue
            if found is not None or parts[-1][0] != 4:
                raise ProtocolError("duplicate or invalid TLS Feature extension")
            sequence = _single_der(parts[-1][1], 48)
            features, offset = set(), 0
            while offset < len(sequence):
                kind, number, offset = _der(sequence, offset)
                if (kind != 2 or not number or number[0] & 128
                        or len(number) > 1 and number[0] == 0 and not number[1] & 128
                        or int.from_bytes(number, "big") > 65535):
                    raise ProtocolError("invalid TLS Feature identifier")
                features.add(int.from_bytes(number, "big"))
            found = frozenset(features)
    return frozenset() if found is None else found


def validate_feature_path(path):
    """Issuer feature sets constrain every immediate child, including CAs."""
    features = tuple(certificate_features(cert) for cert in path)
    for child, issuer in zip(features, features[1:]):
        if not issuer.issubset(child):
            raise ProtocolError("certificate violates issuer TLS Feature constraints")
    return features[0] if features else frozenset()
