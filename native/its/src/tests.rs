use super::*;
use p256::ecdsa::signature::Signer;
use rasn::types::FixedOctetString;
const TEST_PUBLIC:[u8;32]=[0x57,0xdb,0x4b,0x35,0x9f,0x23,0xae,0x5e,0x14,0x6e,0x4e,0x25,0x12,0x05,0x67,0x04,0x72,0x25,0x06,0x34,0x8c,0x15,0x0c,0x14,0x75,0x3d,0x0c,0x93,0x3d,0x04,0xd4,0x21];

fn vector(value:&[u8],width:usize)->Vec<u8>{
    let n=(value.len() as u32).to_be_bytes();[&n[4-width..],value].concat()
}
enum SigningKey { P256(p256::ecdsa::SigningKey), P384(p384::ecdsa::SigningKey) }
fn signing_key(index:u8)->SigningKey{
    SigningKey::P256(p256::ecdsa::SigningKey::from_slice(&[index;32]).unwrap())
}
fn sign(key:&SigningKey,tbs:&[u8],issuer:&[u8])->Signature{
    match key {
        SigningKey::P256(key)=>{
            let input=[Sha256::digest(tbs).to_vec(),Sha256::digest(issuer).to_vec()].concat();
            let sig:p256::ecdsa::Signature=key.sign(&input);let raw=sig.to_bytes();
            Signature::EcdsaNistP256(EcdsaP256Signature{
                r_sig:EccP256CurvePoint::XOnly(FixedOctetString::new(raw[..32].try_into().unwrap())),
                s_sig:FixedOctetString::new(raw[32..].try_into().unwrap())})
        },
        SigningKey::P384(key)=>{
            let input=[Sha384::digest(tbs).to_vec(),Sha384::digest(issuer).to_vec()].concat();
            let sig:p384::ecdsa::Signature=key.sign(&input);let raw=sig.to_bytes();
            Signature::EcdsaNistP384(EcdsaP384Signature{
                r_sig:EccP384CurvePoint::XOnly(FixedOctetString::new(raw[..48].try_into().unwrap())),
                s_sig:FixedOctetString::new(raw[48..].try_into().unwrap())})
        }
    }
}
fn permission()->Option<ServiceSpecificPermissions>{
    Some(ServiceSpecificPermissions::BitmapSsp(BitmapSsp(vec![1,2].into())))
}
fn certificate(key:&SigningKey,issuer:Option<(&CertificateBase,&SigningKey)>,root:bool)->CertificateBase{
    certificate_at(key,issuer,root,1000)
}
fn certificate_at(key:&SigningKey,issuer:Option<(&CertificateBase,&SigningKey)>,root:bool,start:u32)->CertificateBase{
    let public=match key {
        SigningKey::P256(key)=>{
            let point=key.verifying_key().to_encoded_point(true);
            let x=FixedOctetString::new(point.as_bytes()[1..].try_into().unwrap());
            PublicVerificationKey::EcdsaNistP256(if point.as_bytes()[0]==2{EccP256CurvePoint::CompressedY0(x)}else{EccP256CurvePoint::CompressedY1(x)})
        },
        SigningKey::P384(key)=>{
            let point=key.verifying_key().to_encoded_point(true);
            let x=FixedOctetString::new(point.as_bytes()[1..].try_into().unwrap());
            PublicVerificationKey::EcdsaNistP384(if point.as_bytes()[0]==2{EccP384CurvePoint::CompressedY0(x)}else{EccP384CurvePoint::CompressedY1(x)})
        }
    };
    let issue=if root{Some(SequenceOfPsidGroupPermissions(vec![PsidGroupPermissions::builder()
        .subject_permissions(SubjectPermissions::Explicit(SequenceOfPsidSspRange(vec![PsidSspRange{
            psid:Psid(42.into()),ssp_range:Some(SspRange::BitmapSspRange(BitmapSspRange{
                ssp_value:vec![1,0].into(),ssp_bitmask:vec![0xff,0].into()}))
        }]))).min_chain_length(1.into()).chain_length_range(3.into()).build()]))}else{None};
    let tbs=ToBeSignedCertificate::builder()
        .id(CertificateId::None(())).craca_id(HashedId3::from(FixedOctetString::new([0;3])))
        .crl_series(CrlSeries(0)).validity_period(ValidityPeriod{start:Time32(start),duration:Duration::Hours(1)})
        .maybe_app_permissions(if root{None}else{Some(SequenceOfPsidSsp(vec![PsidSsp{psid:Psid(42.into()),ssp:permission()}]))})
        .maybe_cert_issue_permissions(issue)
        .verify_key_indicator(VerificationKeyIndicator::VerificationKey(public))
        .build().unwrap();
    let (issuer_id,issuer_wire,signer)=if let Some((issuer,k))=issuer{
        let bytes=encode(issuer).unwrap();
        let algorithm=key_algorithm(issuer).unwrap();let h=digest(&algorithm,&bytes).unwrap();
        let id=HashedId8::from(FixedOctetString::new(h[h.len()-8..].try_into().unwrap()));
        let id=if algorithm==HashAlgorithm::Sha256{IssuerIdentifier::Sha256AndDigest(id)}else{IssuerIdentifier::Sha384AndDigest(id)};
        (id,bytes,k)
    }else{(IssuerIdentifier::VSelf(if matches!(key,SigningKey::P256(_)){HashAlgorithm::Sha256}else{HashAlgorithm::Sha384}),Vec::new(),key)};
    let signature=sign(signer,&encode(&tbs).unwrap(),&issuer_wire);
    CertificateBase{version:3,r#type:CertificateType::Explicit,issuer:issuer_id,to_be_signed:tbs,signature:Some(signature)}
}
fn make_grant(leaf:&CertificateBase,root:&CertificateBase,leaf_key:&SigningKey,role:u8)->Vec<u8>{
    make_grant_at(leaf,root,leaf_key,role,1_100_000_000,1_300_000_000,1_190_000_000)
}
fn make_grant_at(leaf:&CertificateBase,root:&CertificateBase,leaf_key:&SigningKey,role:u8,start:u64,end:u64,generation:u64)->Vec<u8>{
    let leaf_wire=encode(leaf).unwrap();let root_wire=encode(root).unwrap();
    let chain=[vector(&leaf_wire,3),vector(&root_wire,3)].concat();
    let mut tbs=vec![1,4,0,role];
    tbs.extend(vector(&chain,3));tbs.extend(start.to_be_bytes());tbs.extend(end.to_be_bytes());
    let spki=[X25519_PREFIX,&TEST_PUBLIC].concat();tbs.extend(vector(&spki,3));tbs.extend(vector(b"example.test",2));
    let context=if role==0{b"TLS20 ITS server grant"}else{b"TLS20 ITS client grant"};
    let input=[&[0x20;64][..],context,&[0],&tbs].concat();
    let header=HeaderInfo::builder().psid(Psid(42.into())).generation_time(Time64(generation))
        .pdu_functional_type(PduFunctionalType(1)).build();
    let payload=SignedDataPayload::builder().ext_data_hash(HashedData::Sha256HashedData(
        HashedId32::from(FixedOctetString::new(hash256(&input))))).build().unwrap();
    let to_sign=ToBeSignedData{payload,header_info:header};
    let leaf_hash=digest(&key_algorithm(leaf).unwrap(),&leaf_wire).unwrap();
    let signed=SignedData{hash_id:key_algorithm(leaf).unwrap(),
        signature:sign(leaf_key,&encode(&to_sign).unwrap(),&leaf_wire),tbs_data:to_sign,
        signer:SignerIdentifier::Digest(HashedId8::from(FixedOctetString::new(leaf_hash[leaf_hash.len()-8..].try_into().unwrap())))};
    let proof=Ieee1609Dot2Data{protocol_version:3,content:Ieee1609Dot2Content::SignedData(Box::new(signed))};
    [tbs,vector(&encode(&proof).unwrap(),3)].concat()
}
fn fixture()->(Vec<u8>,Policy,CertificateBase,CertificateBase){
    let root_key=signing_key(1);let leaf_key=signing_key(2);
    let root=certificate(&root_key,None,true);let leaf=certificate(&leaf_key,Some((&root,&root_key)),false);
    let root_wire=encode(&root).unwrap();let leaf_wire=encode(&leaf).unwrap();
    let policy=Policy{now:1_200_000_000,inventory_valid_until:1_250_000_000,max_grant_lifetime:300_000_000,
        role:0,psid:42,scope:b"example.test".to_vec(),ssp:permission(),roots:vec![root_wire],
        authorized_leaves:BTreeSet::from([hash256(&leaf_wire)]),revoked:BTreeSet::new(),regions:Vec::new()};
    (make_grant(&leaf,&root,&leaf_key,0),policy,root,leaf)
}
fn policy_wire(p:&Policy)->Vec<u8>{
    let mut b=b"ITS1".to_vec();
    b.extend(p.now.to_be_bytes());b.extend(p.inventory_valid_until.to_be_bytes());b.extend(p.max_grant_lifetime.to_be_bytes());
    b.push(p.role);b.extend(p.psid.to_be_bytes());b.extend(vector(&p.scope,2));
    b.extend(vector(&p.ssp.as_ref().map(|s|encode(s).unwrap()).unwrap_or_default(),2));
    b.extend(vector(&p.roots.iter().flat_map(|v|vector(v,3)).collect::<Vec<_>>(),3));
    b.extend(vector(&p.authorized_leaves.iter().flat_map(|v|v.iter().copied()).collect::<Vec<_>>(),3));
    b.extend(vector(&p.revoked.iter().flat_map(|v|v.iter().copied()).collect::<Vec<_>>(),3));
    b.extend(vector(&p.regions.iter().flat_map(|v|vector(v,3)).collect::<Vec<_>>(),3));b
}

#[test]
fn full_grant_and_ffi(){
    let (grant,p,_,_)=fixture();let result=authorize(&grant,&p).unwrap();
    assert_eq!(result.x25519_key,TEST_PUBLIC);assert_eq!(result.expires_at,1_250_000_000);
    let policy=policy_wire(&p);let mut output=[0xff;72];
    assert_eq!(unsafe{tls20_its_authorize(grant.as_ptr(),grant.len(),policy.as_ptr(),policy.len(),output.as_mut_ptr(),72)},1);
    assert_eq!(output[..32],TEST_PUBLIC);
    assert_eq!(unsafe{tls20_its_authorize(grant.as_ptr(),3,policy.as_ptr(),policy.len(),output.as_mut_ptr(),72)},0);
    assert_eq!(output,[0;72]);
}
#[test]
fn p384_and_mixed_curve_paths(){
    for mixed in [false,true]{
        let (_,mut policy,_,_)=fixture();
        let root_key=SigningKey::P384(p384::ecdsa::SigningKey::from_slice(&[3;48]).unwrap());
        let leaf_key=if mixed{signing_key(4)}else{SigningKey::P384(p384::ecdsa::SigningKey::from_slice(&[4;48]).unwrap())};
        let root=certificate(&root_key,None,true);let leaf=certificate(&leaf_key,Some((&root,&root_key)),false);
        policy.roots=vec![encode(&root).unwrap()];policy.authorized_leaves=BTreeSet::from([hash256(&encode(&leaf).unwrap())]);
        let grant=make_grant(&leaf,&root,&leaf_key,0);
        assert!(authorize(&grant,&policy).is_ok());
    }
}
#[test]
fn policy_changes_revoke_authority(){
    let (grant,mut p,_,_)=fixture();
    p.role=1;assert!(authorize(&grant,&p).is_err());p.role=0;
    p.scope=b"other.test".to_vec();assert!(authorize(&grant,&p).is_err());p.scope=b"example.test".to_vec();
    p.psid=43;assert!(authorize(&grant,&p).is_err());p.psid=42;
    p.ssp=None;assert!(authorize(&grant,&p).is_err());p.ssp=permission();
    p.revoked.extend(p.authorized_leaves.iter());assert!(authorize(&grant,&p).is_err());p.revoked.clear();
    p.inventory_valid_until=p.now;assert!(authorize(&grant,&p).is_err());p.inventory_valid_until=p.now+1;
    p.max_grant_lifetime=1;assert!(authorize(&grant,&p).is_err());p.max_grant_lifetime=300_000_000;
    p.authorized_leaves.clear();assert!(authorize(&grant,&p).is_err());
}
#[test]
fn signature_and_framing_mutations(){
    let (grant,p,_,_)=fixture();
    for position in 0..grant.len(){
        let mut altered=grant.clone();altered[position]^=0x80;
        assert!(authorize(&altered,&p).is_err(),"accepted changed byte {position}");
    }
    for length in 0..grant.len(){assert!(authorize(&grant[..length],&p).is_err());}
    let mut trailing=grant.clone();trailing.push(0);assert!(authorize(&trailing,&p).is_err());
}
#[test]
fn certificate_permission_failure_is_not_just_signature(){
    let (_,mut p,mut root,_)=fixture();
    root.to_be_signed.cert_issue_permissions.as_mut().unwrap().0[0].min_chain_length=2.into();
    root.signature=Some(sign(&signing_key(1),&encode(&root.to_be_signed).unwrap(),&[]));
    p.roots=vec![encode(&root).unwrap()];
    let leaf=certificate(&signing_key(2),Some((&root,&signing_key(1))),false);
    p.authorized_leaves=BTreeSet::from([hash256(&encode(&leaf).unwrap())]);
    assert!(authorize(&make_grant(&leaf,&root,&signing_key(2),0),&p).is_err());
}
#[test]
fn hostile_sequence_count_is_bounded(){
    // Before vendored guard, this claims 2^63 elements and calls with_capacity.
    assert!(decode::<SequenceOfCertificate>(&[8,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff]).is_err());
}
#[test]
fn export_test_fixture_only_when_requested(){
    let Ok(directory)=std::env::var("TLS20_ITS_FIXTURE_DIR") else{return;};
    let (grant,p,root,leaf)=fixture();
    let dir=std::path::Path::new(&directory);
    // This test never exports production keys and does not run in the library.
    for (name,bytes) in [("grant.bin",grant),("policy.bin",policy_wire(&p)),
        ("root.coer",encode(&root).unwrap()),("leaf.coer",encode(&leaf).unwrap())]{
        std::fs::write(dir.join(name),bytes).unwrap();
    }
    let grant=make_grant(&leaf,&root,&signing_key(2),0);
    let mut cursor=Cursor::new(&grant);cursor.take(4).unwrap();cursor.vector(3).unwrap();cursor.take(16).unwrap();
    cursor.vector(3).unwrap();cursor.vector(2).unwrap();
    let grant_tbs=grant[..cursor.at].to_vec();
    let proof=decode::<Ieee1609Dot2Data>(cursor.vector(3).unwrap()).unwrap();
    let Ieee1609Dot2Content::SignedData(signed)=proof.content else{panic!("fixture proof");};
    fn raw_signature(signature:&Signature)->Vec<u8>{
        let Signature::EcdsaNistP256(sig)=signature else{panic!("fixture signature");};
        let EccP256CurvePoint::XOnly(r)=&sig.r_sig else{panic!("fixture scalar");};
        [r.as_ref(),sig.s_sig.as_ref()].concat()
    }
    for (name,bytes) in [("root-tbs.bin",encode(&root.to_be_signed).unwrap()),
        ("root-signature.bin",raw_signature(root.signature.as_ref().unwrap())),
        ("leaf-tbs.bin",encode(&leaf.to_be_signed).unwrap()),
        ("leaf-signature.bin",raw_signature(leaf.signature.as_ref().unwrap())),
        ("proof-tbs.bin",encode(&signed.tbs_data).unwrap()),
        ("proof-signature.bin",raw_signature(&signed.signature)),("grant-tbs.bin",grant_tbs)]{
        std::fs::write(dir.join(name),bytes).unwrap();
    }
    let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64
        +37_000_000-1_072_915_200_000_000;
    let root_key=signing_key(1);let leaf_key=signing_key(2);
    let root=certificate_at(&root_key,None,true,(now/1_000_000) as u32-200);
    let leaf=certificate_at(&leaf_key,Some((&root,&root_key)),false,(now/1_000_000) as u32-200);
    let leaf_wire=encode(&leaf).unwrap();
    let p=Policy{now,inventory_valid_until:now+1_500_000_000,max_grant_lifetime:2_000_000_000,
        role:0,psid:42,scope:b"example.test".to_vec(),ssp:permission(),roots:vec![encode(&root).unwrap()],
        authorized_leaves:BTreeSet::from([hash256(&leaf_wire)]),revoked:BTreeSet::new(),regions:Vec::new()};
    for (name,bytes) in [
        ("live-server.bin",make_grant_at(&leaf,&root,&leaf_key,0,now-100_000_000,now+1_800_000_000,now-1_000_000)),
        ("live-client.bin",make_grant_at(&leaf,&root,&leaf_key,1,now-100_000_000,now+1_800_000_000,now-1_000_000)),
        ("live-policy.bin",policy_wire(&p)),("live-root.coer",encode(&root).unwrap()),("live-leaf.coer",leaf_wire)
    ]{std::fs::write(dir.join(name),bytes).unwrap();}
}
