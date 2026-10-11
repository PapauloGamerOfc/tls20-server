"""RFC6066 OCSP request framing and request/response matching, not trust.

Matching does not authenticate a responder or a certificate status. The
credential-evidence validator performs those independent checks afterwards.
"""

from dataclasses import dataclass
import hmac

from cryptography import x509
from cryptography.x509 import ocsp

from .credential_selection import _der, _single_der, _name, _oid, _length, _take, _vector
from .errors import ProtocolError

NONCE_OID = "1.3.6.1.5.5.7.48.1.2"


@dataclass(frozen=True)
class OCSPRequest:
    responder_ids: tuple = ()
    nonce: bytes | None = None
    unsupported_critical: bool = False


def parse_status_request(value, *, certificate_request=False):
    if not isinstance(value, bytes):
        raise ProtocolError("invalid status_request encoding", alert=50)
    if certificate_request:
        if value:
            raise ProtocolError("CertificateRequest status_request must be empty", alert=50)
        return OCSPRequest()
    if not value:
        raise ProtocolError("empty status_request", alert=50)
    if value[0] != 1:
        return None  # An unimplemented status protocol is not OCSP.
    identifiers, offset = _take(value, 1, 2)
    extensions, offset = _take(value, offset, 2)
    if offset != len(value):
        raise ProtocolError("trailing status_request bytes", alert=50)
    ids, cursor = [], 0
    while cursor < len(identifiers):
        encoded, cursor = _take(identifiers, cursor, 2)
        tag, content, end = _der(encoded)
        if end != len(encoded) or tag not in (0xa1, 0xa2):
            raise ProtocolError("invalid OCSP ResponderID", alert=50)
        if tag == 0xa1:
            _name(content)
        elif len(_single_der(content, 4)) != 20:
            raise ProtocolError("invalid OCSP responder key hash", alert=50)
        ids.append(encoded)
    nonce, critical, seen = None, False, set()
    if extensions:
        sequence = _single_der(extensions, 48)
        if not sequence:
            raise ProtocolError("empty DER OCSP Extensions", alert=50)
        cursor = 0
        while cursor < len(sequence):
            tag, extension, cursor = _der(sequence, cursor)
            if tag != 48:
                raise ProtocolError("invalid OCSP request extension", alert=50)
            _, _, end = _der(extension)
            oid = _oid(extension[:end])
            if oid in seen:
                raise ProtocolError("duplicate OCSP request extension", alert=47)
            seen.add(oid)
            tag, contents, pos = _der(extension, end)
            is_critical = False
            if tag == 1:
                if contents != b"\xff":
                    raise ProtocolError("noncanonical OCSP critical flag", alert=50)
                is_critical = True
                tag, contents, pos = _der(extension, pos)
            if tag != 4 or pos != len(extension):
                raise ProtocolError("invalid OCSP request extension value", alert=50)
            if oid == NONCE_OID:
                nonce = _single_der(contents, 4)
                if not 1 <= len(nonce) <= 128:
                    raise ProtocolError("invalid OCSP nonce length", alert=50)
            elif is_critical:
                critical = True
    return OCSPRequest(tuple(ids), nonce, critical)


def encode_status_request(responder_ids=(), request_extensions=b""):
    encoded = b"\x01" + _vector(b"".join(_vector(value, 2) for value in responder_ids), 2) + _vector(request_extensions, 2)
    parse_status_request(encoded)
    return encoded


def response_matches_request(response_der, request):
    """False means omit/decline this staple, never claim its request fulfilled."""
    if request is None or request.unsupported_critical:
        return False
    try:
        response = ocsp.load_der_ocsp_response(response_der)
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return False
        if request.responder_ids:
            responder = (b"\xa1" + _length(response.responder_name.public_bytes())
                         if response.responder_name is not None else
                         b"\xa2" + _length(b"\x04" + _length(response.responder_key_hash)))
            if responder not in request.responder_ids:
                return False
        if request.nonce is not None:
            actual = response.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
            if not hmac.compare_digest(actual, request.nonce):
                return False
        return True
    except (ValueError, TypeError, x509.ExtensionNotFound, x509.DuplicateExtension):
        return False
