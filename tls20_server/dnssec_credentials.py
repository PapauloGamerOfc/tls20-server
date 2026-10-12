"""Offline RFC 9102 DNSSEC-chain and DANE validation against explicit anchors.

No resolver AD bit, transport encryption, parsed TLSA or supplied DNSKEY is a
trust decision. dnspython verifies RRSIGs; this module establishes DS/DNSKEY
chains, name/port binding and authenticated NSEC/NSEC3 denial. The caller must
choose an independent credential policy after a validated denial, never after
a malformed/bogus chain. Local budgets protect against validation work bombs.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import struct
import time

import dns.dnssec
import dns.exception
import dns.name
import dns.rdata
import dns.rdatatype as typ
import dns.rrset
from cryptography.hazmat.primitives import serialization

from .errors import ProtocolError
from .pki import _load_pkix_der, validate_server_name


@dataclass(frozen=True)
class DNSSECLimits:
    max_bytes: int = 65535
    max_records: int = 512
    max_validations: int = 256
    max_aliases: int = 16
    max_nsec3_iterations: int = 150


@dataclass(frozen=True)
class ValidatedTLSA:
    service_name: str
    port: int
    owner: str
    records: tuple
    expires_at: float
    authenticated_denial: bool = False


@dataclass(frozen=True)
class DANEAuthorization:
    usage: int | None
    expires_at: float
    # Only a validating callback can supply this path. DANE-EE and legacy
    # boolean callbacks authorize no extra issuer material by themselves.
    validated_path: tuple = ()


@dataclass(frozen=True)
class DNSSECWireEvidence:
    """RFC 9102 section 2.3 Certificate-entry extension, not bare DNS RRs.

    The normative TLS presentation uses a uint16 lifetime followed by a
    uint16-length opaque vector. The appendix's hexadecimal illustration omits
    that vector length; we follow the normative structure, without sniffing two
    ambiguous encodings. Lifetime is a support promise, NOT a DNS TTL, trust
    anchor, or credential authorization.
    """

    support_lifetime_hours: int
    authentication_chain: bytes

    def encode(self):
        if (type(self.support_lifetime_hours) is not int or
                not 0 <= self.support_lifetime_hours <= 65535 or
                not isinstance(self.authentication_chain, bytes) or
                not 1 <= len(self.authentication_chain) <= 65531):
            raise ProtocolError("invalid DNSSEC evidence extension")
        return (self.support_lifetime_hours.to_bytes(2, "big") +
                len(self.authentication_chain).to_bytes(2, "big") + self.authentication_chain)

    @classmethod
    def parse(cls, data):
        if (not isinstance(data, bytes) or not 5 <= len(data) <= 65535 or
                int.from_bytes(data[2:4], "big") != len(data) - 4):
            raise ProtocolError("malformed DNSSEC evidence extension")
        return cls(int.from_bytes(data[:2], "big"), data[4:])


def _name_end(data, offset):
    start = offset
    while offset < len(data):
        size = data[offset]
        offset += 1
        if size & 0xc0 or size > 63 or offset + size > len(data):
            raise ProtocolError("compressed or invalid name in DNSSEC authentication chain")
        if size == 0:
            if offset - start > 255:
                break
            return offset
        offset += size
    raise ProtocolError("truncated or oversized DNSSEC name")


def parse_authentication_chain(data: bytes, *, limits=DNSSECLimits()):
    """Parse the extension's concatenated, uncompressed DNS RRs (no header)."""
    if not isinstance(data, bytes) or not 1 <= len(data) <= limits.max_bytes:
        raise ProtocolError("DNSSEC chain exceeds local byte budget")
    records, cursor, count = {}, 0, 0
    allowed = {typ.DNSKEY, typ.DS, typ.RRSIG, typ.TLSA, typ.NSEC, typ.NSEC3,
               typ.CNAME, typ.DNAME, typ.NS, typ.SOA}
    try:
        while cursor < len(data):
            end = _name_end(data, cursor)
            owner, used = dns.name.from_wire(data[cursor:end], 0)
            if used != end - cursor or end + 10 > len(data):
                raise ProtocolError("invalid DNSSEC resource record")
            kind, rdclass, ttl, size = struct.unpack("!HHIH", data[end:end + 10])
            cursor = end + 10
            raw = data[cursor:cursor + size]
            cursor += size
            count += 1
            if len(raw) != size or count > limits.max_records or rdclass != 1 or kind not in allowed:
                raise ProtocolError("invalid DNSSEC chain record or local record budget")
            # Names within these RDATA forms are required to be uncompressed too.
            if kind in (typ.NSEC, typ.CNAME, typ.DNAME, typ.NS):
                _name_end(raw, 0)
            elif kind == typ.RRSIG:
                _name_end(raw, 18)
            elif kind == typ.SOA:
                _name_end(raw, _name_end(raw, 0))
            rdata = dns.rdata.from_wire(rdclass, kind, raw, 0, len(raw))
            covered = rdata.type_covered if kind == typ.RRSIG else 0
            key = (owner.canonicalize(), kind, covered)
            if key not in records:
                records[key] = dns.rrset.RRset(key[0], rdclass, kind, covered)
            records[key].add(rdata, ttl)
        return records
    except (dns.exception.DNSException, ValueError, IndexError, struct.error) as exc:
        raise ProtocolError("malformed DNSSEC authentication chain") from exc


def _has_type(record, kind):
    for window, bitmap in record.windows:
        if kind // 256 == window:
            position = kind % 256
            return position // 8 < len(bitmap) and bool(bitmap[position // 8] & (0x80 >> (position % 8)))
    return False


def _between(left, value, right):
    # Canonical DNS name order (or NSEC3's fixed-size hash alphabet order).
    if isinstance(left, dns.name.Name):
        compare = lambda a, b: a.fullcompare(b)[1]
    else:
        compare = lambda a, b: (a > b) - (a < b)
    if compare(left, right) < 0:
        return compare(left, value) < 0 and compare(value, right) < 0
    return compare(left, value) < 0 or compare(value, right) < 0


class DNSSECChain:
    def __init__(self, authentication_chain, *, trust_anchors, now=None,
                 limits=DNSSECLimits(), algorithm_policy=None):
        self.records = parse_authentication_chain(authentication_chain, limits=limits)
        self.anchors = {}
        for name, rrset in trust_anchors.items():
            owner = dns.name.from_text(name) if isinstance(name, str) else name
            owner = owner.canonicalize()
            if not owner.is_absolute() or rrset.rdtype not in (typ.DNSKEY, typ.DS) or not rrset:
                raise ProtocolError("invalid explicit DNSSEC trust anchor")
            self.anchors[owner] = rrset
        if not self.anchors or len(self.anchors) > 256:
            raise ProtocolError("bounded explicit DNSSEC trust anchors are required")
        self.now = time.time() if now is None else now
        self.limits, self.policy = limits, algorithm_policy or dns.dnssec.default_policy
        self.keys, self.pending, self.validated = {}, set(), {}
        self.work = 0
        self.expiry = float("inf")

    def _signatures(self, rrset):
        return self.records.get((rrset.name.canonicalize(), typ.RRSIG, rrset.rdtype), ())

    def _verify(self, rrset, signature, keys):
        self.work += 1
        if self.work > self.limits.max_validations:
            raise ProtocolError("DNSSEC validation exceeds local work budget")
        labels = len(rrset.name.labels) - 1
        if signature.labels > labels:
            raise ProtocolError("DNSSEC signature label count exceeds the owner")
        literal_wildcard = rrset.name.labels[0] == b"*" and signature.labels == labels - 1
        if signature.labels < labels and not literal_wildcard:
            if rrset.rdtype not in (typ.TLSA, typ.CNAME) or not self._wildcard_expansion(
                    rrset.name, signature.labels, signature.signer.canonicalize()):
                raise ProtocolError("DNSSEC wildcard RRset requires independent expansion proof")
        try:
            dns.dnssec.validate_rrsig(rrset, signature, {signature.signer: keys},
                                      now=self.now, policy=self.policy)
        except (dns.exception.DNSException, ValueError) as exc:
            raise ProtocolError("DNSSEC signature validation failed") from exc
        self.expiry = min(self.expiry, signature.expiration,
                          self.now + min(rrset.ttl, signature.original_ttl))

    def _wildcard_expansion(self, name, labels, zone):
        closest = dns.name.Name(name.labels[-(labels + 1):])
        next_closer = dns.name.Name(name.labels[-(labels + 2):])
        if not closest.is_subdomain(zone):
            return False
        groups = {}
        for (_, kind, _), rrset in self.records.items():
            if kind not in (typ.NSEC, typ.NSEC3) or len(rrset) != 1:
                continue
            try:
                if self._validate_rrset(rrset) != zone:
                    continue
            except ProtocolError:
                continue
            item = rrset[0]
            if kind == typ.NSEC and item.next.is_subdomain(zone):
                if _between(rrset.name, next_closer, item.next):
                    return True
            elif (kind == typ.NSEC3 and item.algorithm == 1 and item.flags == 0
                    and item.iterations <= self.limits.max_nsec3_iterations and rrset.name.parent() == zone):
                owner = self._nsec3_owner(rrset, item)
                if owner is not None:
                    groups.setdefault((item.salt, item.iterations), []).append((owner, item))
        for (salt, iterations), records in groups.items():
            closest_hash = dns.dnssec.nsec3_hash(closest, salt, iterations, 1)
            next_hash = dns.dnssec.nsec3_hash(next_closer, salt, iterations, 1)
            if any(owner == closest_hash for owner, _ in records) and any(_between(owner, next_hash,
                    base64.b32hexencode(item.next).decode().rstrip('=')) for owner, item in records):
                return True
        return False

    @staticmethod
    def _nsec3_owner(rrset, item):
        # SHA-1 NSEC3 has exactly 160-bit owner/next hashes. DNS labels are
        # arbitrary octets, not necessarily text; malformed authenticated
        # records must never become a denial proof or escape as UnicodeError.
        label = rrset.name.labels[0].upper()
        if (len(label) != 32 or len(item.next) != 20
                or any(value not in b"0123456789ABCDEFGHIJKLMNOPQRSTUV" for value in label)):
            return None
        return label.decode("ascii")

    def _ds_keys(self, zone, keys, ds):
        matching = dns.rrset.RRset(zone, 1, typ.DNSKEY)
        for key in keys:
            if key.protocol != 3 or not key.flags & 256:
                continue
            for digest in ds:
                try:
                    computed = dns.dnssec.make_ds(zone, key, digest.digest_type,
                                                 policy=self.policy, validating=True)
                except (dns.exception.DNSException, ValueError):
                    continue
                if computed == digest:
                    matching.add(key, keys.ttl)
        if not matching:
            raise ProtocolError("DNSSEC delegation has no authenticated key")
        return matching

    def _zone_keys(self, zone):
        zone = zone.canonicalize()
        if zone in self.keys:
            return self.keys[zone]
        if zone in self.pending or len(self.pending) >= 64:
            raise ProtocolError("cyclic or excessive DNSSEC delegation chain")
        self.pending.add(zone)
        try:
            supplied = self.records.get((zone, typ.DNSKEY, 0))
            anchor = self.anchors.get(zone)
            if anchor is not None and anchor.rdtype == typ.DNSKEY and supplied is None:
                self.keys[zone] = anchor
                return anchor
            if supplied is None:
                raise ProtocolError("missing DNSSEC zone keys")
            if anchor is not None:
                authenticated = anchor if anchor.rdtype == typ.DNSKEY else self._ds_keys(zone, supplied, anchor)
            else:
                ds = self.records.get((zone, typ.DS, 0))
                if ds is None:
                    raise ProtocolError("missing authenticated DNSSEC delegation")
                self._validate_rrset(ds, parent_only=True)
                authenticated = self._ds_keys(zone, supplied, ds)
            for signature in self._signatures(supplied):
                if signature.signer.canonicalize() != zone:
                    continue
                try:
                    self._verify(supplied, signature, authenticated)
                except ProtocolError:
                    continue
                self.keys[zone] = supplied
                return supplied
            raise ProtocolError("DNSSEC zone key set is not authenticated")
        finally:
            self.pending.remove(zone)

    def _validate_rrset(self, rrset, *, parent_only=False):
        token = (rrset.name, rrset.rdtype, parent_only)
        if token in self.validated:
            return self.validated[token]
        for signature in self._signatures(rrset):
            zone = signature.signer.canonicalize()
            if not rrset.name.is_subdomain(zone) or parent_only and rrset.name == zone:
                continue
            try:
                self._verify(rrset, signature, self._zone_keys(zone))
            except ProtocolError:
                continue
            self.validated[token] = zone
            return zone
        raise ProtocolError("DNSSEC RRset has no authenticated signature")

    def _denial(self, name):
        nsecs, nsec3s = {}, {}
        for (_, kind, _), rrset in self.records.items():
            if kind not in (typ.NSEC, typ.NSEC3):
                continue
            if len(rrset) != 1:
                continue
            try:
                zone = self._validate_rrset(rrset)
            except ProtocolError:
                continue
            if not name.is_subdomain(zone):
                continue
            for item in rrset:
                if kind == typ.NSEC:
                    if item.next.is_subdomain(zone):
                        nsecs.setdefault(zone, []).append((rrset.name, item))
                elif (item.algorithm == 1 and item.flags in (0, 1)
                        and item.iterations <= self.limits.max_nsec3_iterations
                        and rrset.name.parent() == zone):
                    group = (zone, item.salt, item.iterations)
                    owner = self._nsec3_owner(rrset, item)
                    if owner is not None:
                        nsec3s.setdefault(group, []).append((owner, item))
        for zone, records in nsecs.items():
            exists = {zone}
            for owner, item in records:
                for endpoint in (owner, item.next):
                    while endpoint.is_subdomain(zone):
                        exists.add(endpoint)
                        if endpoint == zone:
                            break
                        endpoint = endpoint.parent()
                if owner == name and not _has_type(item, typ.TLSA) and not _has_type(item, typ.CNAME):
                    return True
                if (name.is_subdomain(owner) and _has_type(item, typ.NS)
                        and not _has_type(item, typ.SOA) and not _has_type(item, typ.DS)):
                    return True  # Authenticated insecure delegation, NOT DANE trust.
            closest = name
            while closest not in exists and closest != zone:
                closest = closest.parent()
            if any(_between(owner, name, item.next) for owner, item in records):
                if closest == name:
                    return True  # Authenticated empty nonterminal, no TLSA/CNAME.
                wildcard = dns.name.from_text("*", origin=closest)
                if any(_between(owner, wildcard, item.next) for owner, item in records):
                    return True
        for (zone, salt, iterations), records in nsec3s.items():
            by_hash = {owner: item for owner, item in records}
            hashed = lambda value: dns.dnssec.nsec3_hash(value, salt, iterations, 1)
            exact = by_hash.get(hashed(name))
            if exact is not None and not _has_type(exact, typ.TLSA) and not _has_type(exact, typ.CNAME):
                return True
            closest = name
            next_closer = None
            while closest.is_subdomain(zone):
                exact = by_hash.get(hashed(closest))
                if exact is not None:
                    if (_has_type(exact, typ.NS) and not _has_type(exact, typ.SOA)
                            and not _has_type(exact, typ.DS)):
                        return True
                    break
                next_closer, closest = closest, closest.parent()
            if exact is None or next_closer is None:
                continue
            def cover(value):
                target = hashed(value)
                return next((item for owner, item in records if _between(owner, target,
                    base64.b32hexencode(item.next).decode("ascii").rstrip("="))), None)
            next_proof = cover(next_closer)
            if next_proof is None:
                continue
            if next_proof.flags & 1:
                return True  # Opt-out is insecure, never a positive TLSA assertion.
            wildcard = dns.name.from_text("*", origin=closest)
            wildcard_exact = by_hash.get(hashed(wildcard))
            if wildcard_exact is not None:
                if not _has_type(wildcard_exact, typ.TLSA) and not _has_type(wildcard_exact, typ.CNAME):
                    return True
            elif cover(wildcard) is not None:
                return True
        return False

    def validate_service(self, service_name, port):
        validate_server_name(service_name)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ProtocolError("invalid DNSSEC service port")
        owner = dns.name.from_text(f"_{port}._tcp.{service_name}.").canonicalize()
        seen = set()
        for _ in range(self.limits.max_aliases + 1):
            if owner in seen:
                raise ProtocolError("DNSSEC service alias loop")
            seen.add(owner)
            tlsa = self.records.get((owner, typ.TLSA, 0))
            if tlsa is not None:
                self._validate_rrset(tlsa)
                return ValidatedTLSA(service_name, port, owner.to_text(), tuple(tlsa), self.expiry)
            alias = self.records.get((owner, typ.CNAME, 0))
            if alias is not None:
                if len(alias) != 1:
                    raise ProtocolError("ambiguous DNSSEC service alias")
                self._validate_rrset(alias)
                owner = alias[0].target.canonicalize()
                continue
            dnames = [rrset for (name, kind, _), rrset in self.records.items()
                      if kind == typ.DNAME and name != owner and owner.is_subdomain(name)]
            if dnames:
                alias = max(dnames, key=lambda record: len(record.name.labels))
                if len(alias) != 1:
                    raise ProtocolError("ambiguous DNSSEC subtree alias")
                self._validate_rrset(alias)
                owner = owner.relativize(alias.name).concatenate(alias[0].target).canonicalize()
                continue
            if self._denial(owner):
                return ValidatedTLSA(service_name, port, owner.to_text(), (), self.expiry, True)
            raise ProtocolError("DNSSEC chain proves neither TLSA nor authenticated denial")
        raise ProtocolError("DNSSEC service aliases exceed local budget")


def match_tlsa(result, material, *, credential_type=0, pkix_validator=None,
               dane_path_validator=None, now=None, return_usage=False,
               return_authorization=False):
    """Apply usage/selector/matching; callers still verify online MAC/Finished.

    pkix_validator(material) must validate path AND service identity and return
    the actual validated path (leaf first). dane_path_validator(material,anchor)
    validates against the DNS-authorized TA with DANE name/path rules and
    returns its actual validated path (leaf first). A legacy True response
    still authorizes usage 2 but supplies no path for evidence validation.
    Absence of either callback does not turn usage 0/1/2 into an EE key pin.
    """
    if not isinstance(result, ValidatedTLSA) or (time.time() if now is None else now) > result.expires_at:
        raise ProtocolError("DNSSEC service evidence is missing or expired")
    def authorized(usage, path=()):
        if return_authorization:
            return DANEAuthorization(usage, result.expires_at, path)
        return usage if return_usage else usage is not None
    if result.authenticated_denial:
        return authorized(None)
    material = tuple(material)
    if not material or credential_type not in (0, 2) or credential_type == 2 and len(material) != 1:
        raise ProtocolError("unsupported DANE credential material")
    certificates = tuple(_load_pkix_der(value) for value in material) if credential_type == 0 else ()
    def validated_path(value):
        path = tuple(value)
        if not path or path[0].public_bytes(serialization.Encoding.DER) != material[0]:
            raise ProtocolError("DANE validator returned a path for a different credential")
        return path
    def matches(record, value, certificate=None):
        if record.selector == 1:
            value = (certificate.public_key().public_bytes(serialization.Encoding.DER,
                      serialization.PublicFormat.SubjectPublicKeyInfo) if certificate else value)
        elif record.selector != 0 or certificate is None:
            return False
        if record.mtype == 1:
            value = hashlib.sha256(value).digest()
        elif record.mtype == 2:
            value = hashlib.sha512(value).digest()
        elif record.mtype != 0:
            return False
        return hmac.compare_digest(value, record.cert)
    for record in result.records:
        if record.usage == 3 and matches(record, material[0], certificates[0] if certificates else None):
            return authorized(3)
        if credential_type != 0:
            continue
        if record.usage in (0, 1) and pkix_validator is not None:
            try:
                path = validated_path(pkix_validator(material))
                candidates = path[:1] if record.usage == 1 else path[1:]
                if any(matches(record, cert.public_bytes(serialization.Encoding.DER), cert) for cert in candidates):
                    return authorized(record.usage, path)
            except ProtocolError:
                continue
        elif record.usage == 2 and dane_path_validator is not None:
            candidates = list(certificates[1:])
            if record.selector == 0 and record.mtype == 0:
                try:
                    candidates.append(_load_pkix_der(record.cert))
                except ProtocolError:
                    continue  # An unusable association does not invalidate its RRset.
            for cert in candidates:
                if matches(record, cert.public_bytes(serialization.Encoding.DER), cert):
                    try:
                        path = dane_path_validator(material, cert)
                        if path is True:
                            return authorized(2)
                        if path is not False and path is not None:
                            return authorized(2, validated_path(path))
                    except ProtocolError:
                        # Rollover RRsets can contain several authorized TAs;
                        # one that cannot build this path is not a global veto.
                        continue
    raise ProtocolError("DNSSEC-authenticated TLSA records do not authorize this credential")


@dataclass(frozen=True)
class DANEPolicy:
    trust_anchors: object
    port: int = 343
    allow_authenticated_denial: bool = False
    pkix_validator: object = None
    dane_path_validator: object = None
    limits: DNSSECLimits = DNSSECLimits()

    def authorize(self, material, credential_type, service_name, evidence, *, now=None,
                  return_authorization=False):
        if not evidence or len(evidence) != len(material):
            raise ProtocolError("DANE policy requires current leaf DNSSEC evidence")
        leaf = dict(evidence[0])
        if 59 not in leaf or any(59 in dict(item) for item in evidence[1:]):
            raise ProtocolError("DNSSEC evidence is absent or not on the end entity")
        moment = time.time() if now is None else now.timestamp()
        envelope = DNSSECWireEvidence.parse(leaf[59])
        result = DNSSECChain(envelope.authentication_chain, trust_anchors=self.trust_anchors,
                            now=moment, limits=self.limits).validate_service(service_name, self.port)
        if result.authenticated_denial and not self.allow_authenticated_denial:
            raise ProtocolError("DANE policy does not permit authenticated absence")
        authorization = match_tlsa(result, material, credential_type=credential_type,
            pkix_validator=self.pkix_validator, dane_path_validator=self.dane_path_validator,
            now=moment, return_authorization=True)
        return authorization if return_authorization else (authorization.usage, authorization.expires_at)
