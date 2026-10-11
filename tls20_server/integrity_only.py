"""RFC 9150 record protection for explicitly non-confidential applications.

This is an HMAC interface, NOT encryption. Ordinary HTTPPS must never enable
these suites. The handshake owns explicit pre-attempt policy and ticket lineage.
Key and IV derivation use the selected hash output length (32 or 48), unlike the
12-byte nonces of the confidential suites.
"""

import hashlib
import hmac

from cryptography.exceptions import InvalidTag


SUITES = {0xC0B4: "sha256", 0xC0B5: "sha384"}


class IntegrityOnly:
    """The RFC's Protect/Unprotect operations, using constant-time tag compare.

    The caller supplies the per-record nonce and complete five-byte header as
    associated data. Sequence numbers and usage limits remain the record layer's
    responsibility. Never expose plaintext before successful tag verification.
    """

    confidential = False

    def __init__(self, key: bytes, hash_name: str):
        if hash_name not in SUITES.values():
            raise ValueError("unsupported integrity-only hash")
        self.hash_name = hash_name
        self.tag_length = hashlib.new(hash_name).digest_size
        if len(key) != self.tag_length:
            raise ValueError("integrity-only key length must equal hash length")
        self._key = bytes(key)

    def _validate(self, nonce, associated_data, length):
        if len(nonce) != self.tag_length:
            raise ValueError("integrity-only nonce must equal hash length")
        if (len(associated_data) != 5 or associated_data[:3] != b"\x17\x03\x03"
                or int.from_bytes(associated_data[3:], "big") != length):
            raise ValueError("invalid protected record header")

    def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes) -> bytes:
        """Protect, retaining the AEAD-shaped interface used by RecordState."""
        self._validate(nonce, associated_data, len(data) + self.tag_length)
        return data + hmac.digest(self._key, nonce + associated_data + data, self.hash_name)

    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes) -> bytes:
        """Unprotect; plaintext is returned only after verification."""
        self._validate(nonce, associated_data, len(data))
        if len(data) < self.tag_length:
            raise InvalidTag
        content, received = data[:-self.tag_length], data[-self.tag_length:]
        expected = hmac.digest(self._key, nonce + associated_data + content, self.hash_name)
        if not hmac.compare_digest(expected, received):
            raise InvalidTag
        return content
