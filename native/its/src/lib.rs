//! Offline ITS-X25519 authentication, with explicit local authorization policy.
//! Parsing is never treated as trust or proof of possession.

use p256::ecdsa::signature::Verifier;
use rasn::{Decode, Encode};
use rasn_its::ieee1609dot2::{base_types::*, *};
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeSet;
mod geography;

type Result<T> = std::result::Result<T, &'static str>;
const MAX_OBJECT: usize = 16384;
const MAX_INPUT: usize = 262144;
const X25519_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0,
];

/// Locally authenticated inventory, not data provided by the peer. Times are
/// IEEE Time64 (microseconds since 2004-01-01 TAI), NOT Unix timestamps.
pub struct Policy {
    pub now: u64,
    pub inventory_valid_until: u64,
    pub max_grant_lifetime: u64,
    pub role: u8,
    pub psid: u64,
    pub scope: Vec<u8>,
    /// The PSID owner's explicit SSP authorization for this TLS20 grant role.
    pub ssp: Option<ServiceSpecificPermissions>,
    pub roots: Vec<Vec<u8>>,
    /// Explicit service/identity binding; trust-root membership alone is not it.
    pub authorized_leaves: BTreeSet<[u8; 32]>,
    pub revoked: BTreeSet<[u8; 32]>,
    /// Provisioned service footprints. At least one must be wholly contained in
    /// every constrained certificate region. No unauthenticated location input.
    pub regions: Vec<Vec<u8>>,
    /// Authenticated local geometry authority statements, each exact canonical
    /// (parent, child) pair. They assert valid regions and child subset parent.
    /// Never populated from peer certificates or learned on first use.
    pub geographic_containment: Vec<(Vec<u8>, Vec<u8>)>,
}

pub struct Authorization {
    pub x25519_key: [u8; 32],
    pub expires_at: u64,
    pub leaf_sha256: [u8; 32],
}

fn encode<T: Encode>(value: &T) -> Result<Vec<u8>> {
    rasn::coer::encode(value).map_err(|_| "COER encoding failed")
}
fn decode<T: Decode + Encode>(wire: &[u8]) -> Result<T> {
    if wire.is_empty() || wire.len() > MAX_OBJECT {
        return Err("ITS object size");
    }
    let value = rasn::coer::decode::<T>(wire).map_err(|_| "invalid COER")?;
    if encode(&value)? != wire {
        return Err("noncanonical or trailing COER");
    }
    Ok(value)
}
fn hash256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
fn contains_region(
    policy: &Policy,
    parent: &GeographicRegion,
    child: &GeographicRegion,
) -> Result<bool> {
    match geography::contains(parent, child) {
        Ok(value) => Ok(value),
        Err("ITS geometry requires provisioned containment attestation") => {
            let pair = (encode(parent)?, encode(child)?);
            Ok(policy.geographic_containment.contains(&pair))
        }
        Err(error) => Err(error),
    }
}
fn digest(algorithm: &HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Sha256 => Ok(Sha256::digest(data).to_vec()),
        HashAlgorithm::Sha384 => Ok(Sha384::digest(data).to_vec()),
        _ => Err("unsupported ITS hash"),
    }
}
fn time_range(cert: &CertificateBase) -> Result<(u64, u64)> {
    let validity = &cert.to_be_signed.validity_period;
    let duration = match validity.duration {
        Duration::Microseconds(v) => u64::from(v),
        Duration::Milliseconds(v) => u64::from(v) * 1000,
        Duration::Seconds(v) => u64::from(v) * 1_000_000,
        Duration::Minutes(v) => u64::from(v) * 60_000_000,
        Duration::Hours(v) => u64::from(v) * 3_600_000_000,
        Duration::SixtyHours(v) => u64::from(v) * 216_000_000_000,
        Duration::Years(v) => u64::from(v) * 31_556_952_000_000,
    };
    let start = u64::from(validity.start.0) * 1_000_000;
    if duration == 0 {
        return Err("empty ITS validity");
    }
    Ok((
        start,
        start.checked_add(duration).ok_or("ITS time overflow")?,
    ))
}
fn key_algorithm(cert: &CertificateBase) -> Result<HashAlgorithm> {
    match cert.to_be_signed.verify_key_indicator {
        VerificationKeyIndicator::VerificationKey(
            PublicVerificationKey::EcdsaNistP256(_)
            | PublicVerificationKey::EcdsaBrainpoolP256r1(_),
        )
        | VerificationKeyIndicator::ReconstructionValue(_) => Ok(HashAlgorithm::Sha256),
        VerificationKeyIndicator::VerificationKey(
            PublicVerificationKey::EcdsaNistP384(_)
            | PublicVerificationKey::EcdsaBrainpoolP384r1(_),
        ) => Ok(HashAlgorithm::Sha384),
        _ => Err("unsupported ITS key"),
    }
}
fn point256(point: &EccP256CurvePoint) -> Result<Vec<u8>> {
    match point {
        EccP256CurvePoint::CompressedY0(x) => Ok([&[2][..], x.as_ref()].concat()),
        EccP256CurvePoint::CompressedY1(x) => Ok([&[3][..], x.as_ref()].concat()),
        _ => Err("ITS profile requires canonical compressed verification key"),
    }
}
fn point384(point: &EccP384CurvePoint) -> Result<Vec<u8>> {
    match point {
        EccP384CurvePoint::CompressedY0(x) => Ok([&[2][..], x.as_ref()].concat()),
        EccP384CurvePoint::CompressedY1(x) => Ok([&[3][..], x.as_ref()].concat()),
        _ => Err("ITS profile requires canonical compressed verification key"),
    }
}
fn verify_signature(
    signer: &CertificateBase,
    signature: &Signature,
    algorithm: &HashAlgorithm,
    tbs: &[u8],
    signer_wire: &[u8],
) -> Result<()> {
    let VerificationKeyIndicator::VerificationKey(key) = &signer.to_be_signed.verify_key_indicator
    else {
        return Err("ITS key has not been reconstructed");
    };
    verify_with_key(key, signature, algorithm, tbs, signer_wire)
}
fn verify_with_key(
    key: &PublicVerificationKey,
    signature: &Signature,
    algorithm: &HashAlgorithm,
    tbs: &[u8],
    signer_wire: &[u8],
) -> Result<()> {
    let message = [digest(algorithm, tbs)?, digest(algorithm, signer_wire)?].concat();
    match (key, signature, algorithm) {
        (
            PublicVerificationKey::EcdsaNistP256(point),
            Signature::EcdsaNistP256(sig),
            HashAlgorithm::Sha256,
        ) => {
            let EccP256CurvePoint::XOnly(r) = &sig.r_sig else {
                return Err("noncanonical ITS signature");
            };
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point256(point)?)
                .map_err(|_| "invalid ITS point")?;
            let sig =
                p256::ecdsa::Signature::from_slice(&[r.as_ref(), sig.s_sig.as_ref()].concat())
                    .map_err(|_| "invalid ITS scalar")?;
            key.verify(&message, &sig)
                .map_err(|_| "ITS signature mismatch")
        }
        (
            PublicVerificationKey::EcdsaNistP384(point),
            Signature::EcdsaNistP384(sig),
            HashAlgorithm::Sha384,
        ) => {
            let EccP384CurvePoint::XOnly(r) = &sig.r_sig else {
                return Err("noncanonical ITS signature");
            };
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point384(point)?)
                .map_err(|_| "invalid ITS point")?;
            let sig =
                p384::ecdsa::Signature::from_slice(&[r.as_ref(), sig.s_sig.as_ref()].concat())
                    .map_err(|_| "invalid ITS scalar")?;
            key.verify(&message, &sig)
                .map_err(|_| "ITS signature mismatch")
        }
        (
            PublicVerificationKey::EcdsaBrainpoolP256r1(point),
            Signature::EcdsaBrainpoolP256r1(sig),
            HashAlgorithm::Sha256,
        ) => {
            use ecdsa17::signature::Verifier;
            let EccP256CurvePoint::XOnly(r) = &sig.r_sig else {
                return Err("noncanonical ITS signature");
            };
            let key = ecdsa17::VerifyingKey::<bp256::r1::BrainpoolP256r1>::from_sec1_bytes(
                &point256(point)?,
            )
            .map_err(|_| "invalid ITS point")?;
            let sig =
                bp256::r1::ecdsa::Signature::from_slice(&[r.as_ref(), sig.s_sig.as_ref()].concat())
                    .map_err(|_| "invalid ITS scalar")?;
            key.verify(&message, &sig)
                .map_err(|_| "ITS signature mismatch")
        }
        (
            PublicVerificationKey::EcdsaBrainpoolP384r1(point),
            Signature::EcdsaBrainpoolP384r1(sig),
            HashAlgorithm::Sha384,
        ) => {
            use ecdsa17::signature::Verifier;
            let EccP384CurvePoint::XOnly(r) = &sig.r_sig else {
                return Err("noncanonical ITS signature");
            };
            let key = ecdsa17::VerifyingKey::<bp384::r1::BrainpoolP384r1>::from_sec1_bytes(
                &point384(point)?,
            )
            .map_err(|_| "invalid ITS point")?;
            let sig =
                bp384::r1::ecdsa::Signature::from_slice(&[r.as_ref(), sig.s_sig.as_ref()].concat())
                    .map_err(|_| "invalid ITS scalar")?;
            key.verify(&message, &sig)
                .map_err(|_| "ITS signature mismatch")
        }
        _ => Err("ITS signature/key/hash mismatch"),
    }
}
/// IEEE 1609.2a-2017 section 5.3.2 and SEC4 section 3.7. The 256-bit
/// digest is interpreted without SEC4's truncation; scalar reduction performed
/// by the curve library is equivalent for multiplying a point of order n.
fn reconstruct_key(
    cert: &CertificateBase,
    issuer_key: &PublicVerificationKey,
    issuer_wire: &[u8],
) -> Result<PublicVerificationKey> {
    let VerificationKeyIndicator::ReconstructionValue(point) =
        &cert.to_be_signed.verify_key_indicator
    else {
        return Err("ITS reconstruction point absent");
    };
    if !cert.is_implicit() || !matches!(cert.issuer, IssuerIdentifier::Sha256AndDigest(_)) {
        return Err("invalid implicit ITS certificate");
    }
    let tbs = encode(&cert.to_be_signed)?;
    let e = hash256(&[hash256(&tbs).as_slice(), hash256(issuer_wire).as_slice()].concat());
    match issuer_key {
        PublicVerificationKey::EcdsaNistP256(parent) => {
            use p256::elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint};
            let reconstruction = p256::PublicKey::from_sec1_bytes(&point256(point)?)
                .map_err(|_| "invalid reconstruction point")?;
            let issuer = p256::PublicKey::from_sec1_bytes(&point256(parent)?)
                .map_err(|_| "invalid issuer point")?;
            let scalar = <p256::Scalar as Reduce<p256::U256>>::reduce_bytes(&e.into());
            let q = p256::ProjectivePoint::from(*reconstruction.as_affine()) * scalar
                + p256::ProjectivePoint::from(*issuer.as_affine());
            let key = p256::PublicKey::from_affine(q.to_affine())
                .map_err(|_| "identity implicit ITS key")?;
            let wire = key.to_encoded_point(true);
            let x = rasn::types::FixedOctetString::new(
                wire.as_bytes()[1..].try_into().map_err(|_| "point width")?,
            );
            Ok(PublicVerificationKey::EcdsaNistP256(
                if wire.as_bytes()[0] == 2 {
                    EccP256CurvePoint::CompressedY0(x)
                } else {
                    EccP256CurvePoint::CompressedY1(x)
                },
            ))
        }
        PublicVerificationKey::EcdsaBrainpoolP256r1(parent) => {
            use bp256::elliptic_curve::{ops::Reduce, sec1::ToSec1Point};
            type Curve = bp256::r1::BrainpoolP256r1;
            let reconstruction =
                bp256::elliptic_curve::PublicKey::<Curve>::from_sec1_bytes(&point256(point)?)
                    .map_err(|_| "invalid reconstruction point")?;
            let issuer =
                bp256::elliptic_curve::PublicKey::<Curve>::from_sec1_bytes(&point256(parent)?)
                    .map_err(|_| "invalid issuer point")?;
            let scalar = <bp256::Scalar as Reduce<bp256::r1::FieldBytes>>::reduce(&e.into());
            let q = bp256::r1::ProjectivePoint::from(*reconstruction.as_affine()) * scalar
                + bp256::r1::ProjectivePoint::from(*issuer.as_affine());
            let key = bp256::elliptic_curve::PublicKey::<Curve>::from_affine(q.to_affine())
                .map_err(|_| "identity implicit ITS key")?;
            let wire = key.to_sec1_point(true);
            let x = rasn::types::FixedOctetString::new(
                wire.as_bytes()[1..].try_into().map_err(|_| "point width")?,
            );
            Ok(PublicVerificationKey::EcdsaBrainpoolP256r1(
                if wire.as_bytes()[0] == 2 {
                    EccP256CurvePoint::CompressedY0(x)
                } else {
                    EccP256CurvePoint::CompressedY1(x)
                },
            ))
        }
        _ => Err("implicit ITS issuer must use a supported 256-bit curve"),
    }
}
fn issuer_hash(cert: &CertificateBase, signer_wire: &[u8]) -> Result<HashAlgorithm> {
    let (algorithm, identity) = match &cert.issuer {
        IssuerIdentifier::Sha256AndDigest(v) => (HashAlgorithm::Sha256, v.as_ref()),
        IssuerIdentifier::Sha384AndDigest(v) => (HashAlgorithm::Sha384, v.as_ref()),
        _ => return Err("non-root ITS issuer must identify its issuer"),
    };
    let hashed = digest(&algorithm, signer_wire)?;
    if &hashed[hashed.len() - 8..] != identity {
        return Err("ITS issuer identifier mismatch");
    }
    Ok(algorithm)
}
fn profile_certificate(cert: &CertificateBase, policy: &Policy) -> Result<()> {
    if cert.version != 3 || !(cert.is_explicit() || cert.is_implicit()) {
        return Err("inconsistent ITS certificate type");
    }
    key_algorithm(cert)?;
    let t = &cert.to_be_signed;
    // Unknown extension semantics cannot silently enlarge delegated authority.
    if t.app_extensions.is_some()
        || t.cert_issue_extensions.is_some()
        || t.cert_request_extension.is_some()
    {
        return Err("unsupported ITS certificate profile extension");
    }
    // Enrollment capabilities and encryption keys confer no TLS grant authority.
    // Recognize their syntax without treating them as application permissions.
    if let Some(flags) = &t.flags {
        if flags.iter().skip(1).any(|v| *v) || (flags[0] && t.cert_issue_permissions.is_none()) {
            return Err("unknown or misplaced ITS certificate flags");
        }
    }
    if let Some(request) = &t.cert_request_permissions {
        validate_groups(request, true)?;
    }
    if let Some(encryption) = &t.encryption_key {
        if encryption.supported_symm_alg != SymmAlgorithm::Aes128Ccm {
            return Err("unsupported ITS encryption algorithm");
        }
        match &encryption.public_key {
            BasePublicEncryptionKey::EciesNistP256(point) => {
                p256::PublicKey::from_sec1_bytes(&point256(point)?)
                    .map_err(|_| "invalid ITS encryption point")?;
            }
            BasePublicEncryptionKey::EciesBrainpoolP256r1(point) => {
                bp256::elliptic_curve::PublicKey::<bp256::r1::BrainpoolP256r1>::from_sec1_bytes(
                    &point256(point)?,
                )
                .map_err(|_| "invalid ITS encryption point")?;
            }
            _ => return Err("unsupported ITS encryption point"),
        }
    }
    if let Some(region) = &t.region {
        geography::validate(region)?;
        let mut authorized = false;
        for configured in &policy.regions {
            let footprint: GeographicRegion = decode(configured)?;
            if contains_region(policy, region, &footprint)? {
                authorized = true;
                break;
            }
        }
        if !authorized {
            return Err("ITS region not authorized for service");
        }
    }
    let (start, end) = time_range(cert)?;
    if policy.now < start || policy.now >= end {
        return Err("ITS certificate expired or not yet valid");
    }
    if let Some(app) = &t.app_permissions {
        let mut psids = BTreeSet::new();
        if app.0.is_empty()
            || app.0.len() > 256
            || app.0.iter().any(|p| !psids.insert(p.psid.clone()))
        {
            return Err("empty, excessive or duplicate ITS application permissions");
        }
    }
    if let Some(issue) = &t.cert_issue_permissions {
        validate_groups(issue, false)?;
    }
    Ok(())
}
fn validate_groups(groups: &SequenceOfPsidGroupPermissions, request: bool) -> Result<()> {
    if groups.0.is_empty() || groups.0.len() > 256 {
        return Err("ITS issuance permission group count");
    }
    let mut all = false;
    for group in &groups.0 {
        if request {
            permission_bounds(group)?;
        } else {
            issuance_bounds(group)?;
        }
        match &group.subject_permissions {
            SubjectPermissions::All(()) => {
                if all {
                    return Err("duplicate ITS all-permission group");
                }
                all = true;
            }
            SubjectPermissions::Explicit(values) => {
                let mut psids = BTreeSet::new();
                if values.0.is_empty()
                    || values.0.len() > 256
                    || values.0.iter().any(|p| !psids.insert(p.psid.clone()))
                {
                    return Err("empty, excessive or duplicate ITS issuance PSID");
                }
                for permission in &values.0 {
                    if let Some(SspRange::BitmapSspRange(v)) = &permission.ssp_range {
                        if v.ssp_value.len() != v.ssp_bitmask.len() {
                            return Err("ITS bitmap SSP width mismatch");
                        }
                    }
                }
            }
            _ => return Err("unsupported ITS subject permission"),
        }
    }
    Ok(())
}
fn permission_range<'a>(
    group: &'a PsidGroupPermissions,
    psid: &Psid,
    groups: &SequenceOfPsidGroupPermissions,
) -> Result<Option<&'a SspRange>> {
    match &group.subject_permissions {
        // IEEE1609.2's all is a default for PSIDs not explicitly listed. It
        // must never override another group's narrower grant for this PSID.
        SubjectPermissions::All(())
            if !groups.0.iter().any(|p| {
                matches!(&p.subject_permissions,
            SubjectPermissions::Explicit(values) if values.0.iter().any(|v|&v.psid==psid))
            }) =>
        {
            Ok(None)
        }
        SubjectPermissions::Explicit(p) => {
            p.0.iter()
                .find(|v| &v.psid == psid)
                .map(|v| v.ssp_range.as_ref())
                .ok_or("ITS issuance PSID not granted")
        }
        _ => Err("unsupported ITS subject permission"),
    }
}
fn ssp_allowed(range: Option<&SspRange>, ssp: &Option<ServiceSpecificPermissions>) -> bool {
    match (range, ssp) {
        (None | Some(SspRange::All(())), _) => true,
        (Some(SspRange::Opaque(values)), None) => values.iter().any(|v| v.is_empty()),
        (Some(SspRange::Opaque(values)), Some(ServiceSpecificPermissions::Opaque(v))) => {
            values.contains(v)
        }
        (
            Some(SspRange::BitmapSspRange(range)),
            Some(ServiceSpecificPermissions::BitmapSsp(value)),
        ) => {
            let value: &[u8] = value.0.as_ref();
            value.len() == range.ssp_value.len()
                && value.len() == range.ssp_bitmask.len()
                && value
                    .iter()
                    .zip(range.ssp_value.iter())
                    .zip(range.ssp_bitmask.iter())
                    .all(|((&a, &b), &m)| a & m == b & m)
        }
        _ => false,
    }
}
fn range_subset(child: Option<&SspRange>, parent: Option<&SspRange>) -> bool {
    match (child, parent) {
        (_, None | Some(SspRange::All(()))) => true,
        (Some(SspRange::Opaque(a)), Some(SspRange::Opaque(b))) => a.iter().all(|v| b.contains(v)),
        (Some(SspRange::BitmapSspRange(a)), Some(SspRange::BitmapSspRange(b))) => {
            let n = a.ssp_value.len();
            n == a.ssp_bitmask.len()
                && n == b.ssp_value.len()
                && n == b.ssp_bitmask.len()
                && (0..n).all(|i| {
                    a.ssp_bitmask[i] & b.ssp_bitmask[i] == b.ssp_bitmask[i]
                        && a.ssp_value[i] & b.ssp_bitmask[i] == b.ssp_value[i] & b.ssp_bitmask[i]
                })
        }
        _ => false,
    }
}
fn permission_bounds(group: &PsidGroupPermissions) -> Result<(i64, i64)> {
    let min = i64::try_from(&group.min_chain_length).map_err(|_| "ITS chain bound")?;
    let range = i64::try_from(&group.chain_length_range).map_err(|_| "ITS chain bound")?;
    if min < 0
        || range < -1
        || !group.ee_type.0[..2].iter().any(|v| *v)
        || group.ee_type.0[2..].iter().any(|x| *x)
    {
        return Err("invalid ITS issuance bounds or end entity type");
    }
    Ok((
        min,
        if range == -1 {
            i64::MAX
        } else {
            min.checked_add(range).ok_or("ITS chain overflow")?
        },
    ))
}
fn issuance_bounds(group: &PsidGroupPermissions) -> Result<(i64, i64)> {
    let bounds = permission_bounds(group)?;
    if bounds.0 == 0 {
        return Err("zero ITS issuing chain length");
    }
    Ok(bounds)
}
fn issuer_permissions(
    parent: &CertificateBase,
    child: &CertificateBase,
    depth: usize,
    policy: &Policy,
) -> Result<()> {
    let groups = parent
        .to_be_signed
        .cert_issue_permissions
        .as_ref()
        .ok_or("ITS issuer lacks issuance permissions")?;
    let requested = Psid(policy.psid.into());
    if !groups.0.iter().any(|p| {
        let Ok((min, max)) = issuance_bounds(p) else {
            return false;
        };
        p.ee_type.0[0]
            && (depth as i64) >= min
            && (depth as i64) <= max
            && permission_range(p, &requested, groups)
                .is_ok_and(|range| ssp_allowed(range, &policy.ssp))
    }) {
        return Err("ITS issuer does not authorize grant permission/path");
    }
    let (ps, pe) = time_range(parent)?;
    let (cs, ce) = time_range(child)?;
    if cs < ps || ce > pe {
        return Err("ITS child lifetime exceeds issuer");
    }
    if let Some(parent_region) = &parent.to_be_signed.region {
        if let Some(child_region) = &child.to_be_signed.region {
            if !contains_region(policy, parent_region, child_region)? {
                return Err("ITS child region exceeds issuer");
            }
        }
    }
    if let Some(app) = &child.to_be_signed.app_permissions {
        for app in &app.0 {
            if !groups.0.iter().any(|p| {
                p.ee_type.0[0]
                    && issuance_bounds(p).is_ok_and(|(min, max)| min <= 1 && max >= 1)
                    && permission_range(p, &app.psid, groups)
                        .is_ok_and(|range| ssp_allowed(range, &app.ssp))
            }) {
                return Err("ITS child application permission exceeds issuer");
            }
        }
    }
    if let Some(child_groups) = &child.to_be_signed.cert_issue_permissions {
        for c in &child_groups.0 {
            let (cmin, cmax) = issuance_bounds(c)?;
            let bounds_and_type = |p: &PsidGroupPermissions| {
                let Ok((min, max)) = issuance_bounds(p) else {
                    return false;
                };
                cmin.checked_add(1).is_some_and(|n| n >= min)
                    && (max == i64::MAX || cmax.checked_add(1).is_some_and(|n| n <= max))
                    && !c
                        .ee_type
                        .0
                        .iter()
                        .zip(p.ee_type.0.iter())
                        .any(|(a, b)| *a && !*b)
            };
            let valid=match &c.subject_permissions {
                SubjectPermissions::All(())=>groups.0.iter().any(|p|bounds_and_type(p)&&matches!(p.subject_permissions,SubjectPermissions::All(())))
                    && groups.0.iter().all(|p|match &p.subject_permissions {
                        SubjectPermissions::Explicit(values)=>values.0.iter().all(|v|child_groups.0.iter().any(|c|matches!(&c.subject_permissions,
                            SubjectPermissions::Explicit(children) if children.0.iter().any(|child|child.psid==v.psid)))),
                        _=>true,
                    }),
                SubjectPermissions::Explicit(values)=>values.0.iter().all(|v|groups.0.iter().any(|p|
                    bounds_and_type(p) && permission_range(p,&v.psid,groups).is_ok_and(|range|range_subset(v.ssp_range.as_ref(),range)))),
                _=>false,
            };
            if !valid {
                return Err("ITS child delegates beyond issuer permissions");
            }
        }
    }
    Ok(())
}

struct Cursor<'a> {
    wire: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn new(wire: &'a [u8]) -> Self {
        Self { wire, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("length overflow")?;
        let value = self.wire.get(self.at..end).ok_or("truncated ITS input")?;
        self.at = end;
        Ok(value)
    }
    fn integer(&mut self, n: usize) -> Result<u64> {
        if n > 8 {
            return Err("integer width");
        }
        Ok(self
            .take(n)?
            .iter()
            .fold(0, |n, v| (n << 8) | u64::from(*v)))
    }
    fn vector(&mut self, n: usize) -> Result<&'a [u8]> {
        let len = self.integer(n)? as usize;
        self.take(len)
    }
    fn done(&self) -> bool {
        self.at == self.wire.len()
    }
}
fn vectors(wire: &[u8], max: usize) -> Result<Vec<Vec<u8>>> {
    let mut cursor = Cursor::new(wire);
    let mut output = Vec::new();
    while !cursor.done() {
        if output.len() >= max {
            return Err("ITS vector count");
        }
        let value = cursor.vector(3)?;
        if value.is_empty() || value.len() > MAX_OBJECT {
            return Err("ITS vector size");
        }
        output.push(value.to_vec());
    }
    Ok(output)
}

/// Authenticate an offline grant, NOT the live peer. The caller must still
/// verify the role-specific X25519 MAC and Finished with this returned key.
pub fn authorize(grant: &[u8], policy: &Policy) -> Result<Authorization> {
    if grant.len() > MAX_INPUT
        || policy.role > 1
        || policy.roots.is_empty()
        || policy.roots.len() > 32
        || policy.authorized_leaves.is_empty()
        || policy.authorized_leaves.len() > 1024
        || policy.revoked.len() > 4096
        || policy.regions.len() > 32
        || policy.geographic_containment.len() > 256
        || policy.scope.len() > 65535
        || policy.inventory_valid_until <= policy.now
        || policy.max_grant_lifetime == 0
    {
        return Err("ITS local policy is absent, stale or invalid");
    }
    let mut cursor = Cursor::new(grant);
    if cursor.integer(1)? != 1
        || cursor.integer(2)? != 0x0400
        || cursor.integer(1)? != u64::from(policy.role)
    {
        return Err("ITS grant version or role mismatch");
    }
    let mut chain = vectors(cursor.vector(3)?, 8)?;
    if chain.is_empty() {
        return Err("empty ITS chain");
    }
    let start = cursor.integer(8)?;
    let end = cursor.integer(8)?;
    let spki = cursor.vector(3)?;
    if spki.len() != 44 || !spki.starts_with(X25519_PREFIX) {
        return Err("ITS grant X25519 SPKI");
    }
    if cursor.vector(2)? != policy.scope
        || start > end
        || policy.now < start
        || policy.now >= end
        || end - start > policy.max_grant_lifetime
    {
        return Err("ITS grant scope or validity mismatch");
    }
    let tbs_end = cursor.at;
    let proof_wire = cursor.vector(3)?;
    if !cursor.done() {
        return Err("trailing ITS grant");
    }
    let leaf_hash = hash256(&chain[0]);
    if !policy.authorized_leaves.contains(&leaf_hash) {
        return Err("ITS leaf has no explicit service/role binding");
    }
    let mut certificates = chain
        .iter()
        .map(|v| decode::<CertificateBase>(v))
        .collect::<Result<Vec<_>>>()?;
    // Find a provisioned final anchor; only explicit, unambiguous chains are
    // supported. No online discovery, implicit root creation or best effort.
    if !policy
        .roots
        .contains(chain.last().ok_or("empty ITS chain")?)
    {
        let last = certificates.last().ok_or("empty ITS chain")?;
        let roots = policy
            .roots
            .iter()
            .filter(|root| issuer_hash(last, root).is_ok())
            .collect::<Vec<_>>();
        if roots.len() != 1 || chain.len() >= 8 {
            return Err("ITS chain has no unique provisioned anchor");
        }
        certificates.push(decode(roots[0])?);
        chain.push(roots[0].clone());
    }
    let mut seen = BTreeSet::new();
    for (cert, wire) in certificates.iter().zip(chain.iter()) {
        let id = hash256(wire);
        if !seen.insert(id) || policy.revoked.contains(&id) {
            return Err("ITS revoked or cyclic chain");
        }
        profile_certificate(cert, policy)?;
    }
    let leaf = &certificates[0];
    let app = leaf
        .to_be_signed
        .app_permissions
        .as_ref()
        .ok_or("ITS leaf has no application permission")?;
    if !app
        .0
        .iter()
        .any(|p| p.psid.0 == policy.psid.into() && p.ssp == policy.ssp)
    {
        return Err("ITS leaf is not the authorized end-entity permission");
    }
    let (leaf_start, leaf_end) = time_range(leaf)?;
    if start < leaf_start || end > leaf_end {
        return Err("ITS grant exceeds leaf validity");
    }
    let root = certificates.last().ok_or("empty ITS chain")?;
    let IssuerIdentifier::VSelf(root_hash) = &root.issuer else {
        return Err("provisioned ITS anchor not self-issued");
    };
    verify_signature(
        root,
        root.signature.as_ref().ok_or("ITS root signature absent")?,
        root_hash,
        &encode(&root.to_be_signed)?,
        &[],
    )?;
    let VerificationKeyIndicator::VerificationKey(mut current_key) =
        root.to_be_signed.verify_key_indicator.clone()
    else {
        return Err("ITS anchor requires an explicit verification key");
    };
    let mut inherited_region = root.to_be_signed.region.as_ref();
    for i in (0..certificates.len() - 1).rev() {
        let child = &certificates[i];
        let parent = &certificates[i + 1];
        let algorithm = issuer_hash(child, &chain[i + 1])?;
        issuer_permissions(parent, child, i + 1, policy)?;
        if let Some(child_region) = &child.to_be_signed.region {
            if let Some(parent_region) = inherited_region {
                if !contains_region(policy, parent_region, child_region)? {
                    return Err("ITS child region exceeds inherited issuer region");
                }
            }
            inherited_region = Some(child_region);
        }
        if child.is_implicit() {
            current_key = reconstruct_key(child, &current_key, &chain[i + 1])?;
        } else {
            verify_with_key(
                &current_key,
                child
                    .signature
                    .as_ref()
                    .ok_or("ITS certificate signature absent")?,
                &algorithm,
                &encode(&child.to_be_signed)?,
                &chain[i + 1],
            )?;
            let VerificationKeyIndicator::VerificationKey(key) =
                &child.to_be_signed.verify_key_indicator
            else {
                return Err("ITS verification key absent");
            };
            current_key = key.clone();
        }
    }
    let proof = decode::<Ieee1609Dot2Data>(proof_wire)?;
    if proof.protocol_version != 3 {
        return Err("ITS proof version");
    }
    let Ieee1609Dot2Content::SignedData(signed) = proof.content else {
        return Err("ITS proof must be SignedData");
    };
    let payload = &signed.tbs_data.payload;
    let header = &signed.tbs_data.header_info;
    if payload.data.is_some() || payload.omitted.is_some() {
        return Err("ITS proof payload form");
    }
    let context = if policy.role == 0 {
        b"TLS20 ITS server grant"
    } else {
        b"TLS20 ITS client grant"
    };
    let input = [&[0x20; 64][..], context, &[0], &grant[..tbs_end]].concat();
    let Some(HashedData::Sha256HashedData(expected)) = &payload.ext_data_hash else {
        return Err("ITS extDataHash algorithm");
    };
    if expected.as_ref() != hash256(&input) {
        return Err("ITS extDataHash mismatch");
    }
    let generation = header
        .generation_time
        .as_ref()
        .ok_or("ITS generationTime absent")?
        .0;
    if header.psid.0 != policy.psid.into()
        || generation < start
        || generation > end
        || generation > policy.now
        || header.pdu_functional_type.as_ref().map(|v| v.0) != Some(1)
        || header.expiry_time.is_some()
        || header.generation_location.is_some()
        || header.p2pcd_learning_request.is_some()
        || header.missing_crl_identifier.is_some()
        || header.encryption_key.is_some()
        || header.inline_p2pcd_request.is_some()
        || header.requested_certificate.is_some()
        || header.contributed_extensions.is_some()
    {
        return Err("ITS proof HeaderInfo violates grant profile");
    }
    match &signed.signer {
        SignerIdentifier::Digest(id) => {
            let h = digest(&key_algorithm(leaf)?, &chain[0])?;
            if id.as_ref() != &h[h.len() - 8..] {
                return Err("ITS proof signer mismatch");
            }
        }
        SignerIdentifier::Certificate(values)
            if values.0.len() == 1 && encode(&values.0[0])? == chain[0] => {}
        _ => return Err("ITS proof signer is not exact leaf"),
    }
    verify_with_key(
        &current_key,
        &signed.signature,
        &signed.hash_id,
        &encode(&signed.tbs_data)?,
        &chain[0],
    )?;
    Ok(Authorization {
        x25519_key: spki[12..].try_into().map_err(|_| "X25519 key")?,
        expires_at: end.min(policy.inventory_valid_until),
        leaf_sha256: leaf_hash,
    })
}

fn parse_policy(wire: &[u8]) -> Result<Policy> {
    let mut c = Cursor::new(wire);
    if wire.len() > MAX_INPUT || c.take(4)? != b"ITS1" {
        return Err("ITS policy encoding");
    }
    let now = c.integer(8)?;
    let inventory_valid_until = c.integer(8)?;
    let max_grant_lifetime = c.integer(8)?;
    let role = c.integer(1)? as u8;
    let psid = c.integer(8)?;
    let scope = c.vector(2)?.to_vec();
    let ssp = c.vector(2)?;
    let ssp = if ssp.is_empty() {
        None
    } else {
        Some(decode(ssp)?)
    };
    let roots = vectors(c.vector(3)?, 32)?;
    fn hashes(c: &mut Cursor) -> Result<BTreeSet<[u8; 32]>> {
        let wire = c.vector(3)?;
        if wire.len() % 32 != 0 || wire.len() > 4096 * 32 {
            return Err("ITS policy fingerprint list");
        }
        Ok(wire
            .chunks_exact(32)
            .map(|x| x.try_into().expect("fixed chunk"))
            .collect())
    }
    let authorized_leaves = hashes(&mut c)?;
    let revoked = hashes(&mut c)?;
    let regions = vectors(c.vector(3)?, 32)?;
    let mut geographic_containment = Vec::new();
    if !c.done() {
        if c.take(4)? != b"GEO1" {
            return Err("unknown ITS policy extension");
        }
        let mut pairs = Cursor::new(c.vector(3)?);
        while !pairs.done() {
            if geographic_containment.len() >= 256 {
                return Err("ITS geometry attestation count");
            }
            let parent = pairs.vector(3)?.to_vec();
            let child = pairs.vector(3)?.to_vec();
            let p: GeographicRegion = decode(&parent)?;
            let ch: GeographicRegion = decode(&child)?;
            geography::validate(&p)?;
            geography::validate(&ch)?;
            geographic_containment.push((parent, child));
        }
    }
    if !c.done() {
        return Err("trailing ITS policy");
    }
    Ok(Policy {
        now,
        inventory_valid_until,
        max_grant_lifetime,
        role,
        psid,
        scope,
        ssp,
        roots,
        authorized_leaves,
        revoked,
        regions,
        geographic_containment,
    })
}

/// Stable C ABI, no allocator crosses the boundary. Output: X25519 raw key32,
/// expiry Time64 big-endian8, leaf SHA25632. The caller supplies valid slices.
/// All outputs are zeroed on every failure; errors and panics fail closed.
#[no_mangle]
pub unsafe extern "C" fn tls20_its_authorize(
    grant: *const u8,
    grant_len: usize,
    policy: *const u8,
    policy_len: usize,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if output.is_null() || output_len != 72 {
        return 0;
    }
    unsafe {
        std::ptr::write_bytes(output, 0, 72);
    }
    if grant.is_null() || policy.is_null() || grant_len > MAX_INPUT || policy_len > MAX_INPUT {
        return 0;
    }
    let result = std::panic::catch_unwind(|| {
        let grant = unsafe { std::slice::from_raw_parts(grant, grant_len) };
        let policy = unsafe { std::slice::from_raw_parts(policy, policy_len) };
        authorize(grant, &parse_policy(policy)?)
    });
    if let Ok(Ok(a)) = result {
        let value = [
            a.x25519_key.as_slice(),
            &a.expires_at.to_be_bytes(),
            a.leaf_sha256.as_slice(),
        ]
        .concat();
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr(), output, 72);
        }
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn tls20_its_abi_version() -> u32 {
    1
}

#[cfg(test)]
mod tests;
