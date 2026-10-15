//! CAdES-BES / CAdES-EPES signatures (ETSI TS 101 733 / EN 319 122), with the
//! same structure AutoFirma produces:
//!
//! * signed attributes `contentType`, `signingTime`, `contentHint` (when a
//!   description is known), `messageDigest`, `signingCertificateV2` and, for EPES,
//!   `signaturePolicyIdentifier`;
//! * the whole certificate chain in `certificates`;
//! * `rsaEncryption` / `ecdsa-with-SHAxxx` as signature algorithm.
//!
//! Signing is done in two phases ([`prepare`] and [`PreparedSignature::finish`]) so
//! that the private key operation can happen elsewhere (triphase signing, smart
//! cards, asynchronous keys).

use std::time::Duration;

use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedAttributes, SignedData, SignerIdentifier,
        SignerInfo, SignerInfos,
    },
};
use const_oid::ObjectIdentifier;
use der::{
    Decode, Encode, Sequence, Tag,
    asn1::{Any, GeneralizedTime, Ia5String, OctetString, SetOfVec, UtcTime},
};
use pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    Certificate, attr::Attribute, ext::pkix::name::GeneralName, serial_number::SerialNumber,
    time::Time,
};

use crate::{
    algorithm::{KeyType, cms_signature_algorithm, digest_of_signature_algorithm, oid},
    cert::CertificateInfo,
    digest::DigestAlgorithm,
    error::{Error, Result},
    keystore::SigningKey,
    policy::SignaturePolicy,
};

/// Whether the signed data is included in the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureMode {
    /// Detached signature: the data is not included (AutoFirma's default, `mode=explicit`).
    Explicit,
    /// Attached signature: the data is included (`mode=implicit`).
    Implicit,
}

/// Parameters of a CAdES signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CadesParams {
    /// Digest algorithm (AutoFirma's default is SHA-512).
    pub digest: DigestAlgorithm,
    /// Explicit (detached) or implicit (attached).
    pub mode: SignatureMode,
    /// Signature policy, turning the signature into CAdES-EPES.
    pub policy: Option<SignaturePolicy>,
    /// Signing time, seconds since the Unix epoch.
    pub signing_time: i64,
    /// Description of the content for the `contentHint` attribute.
    pub content_description: Option<String>,
}

/// A signature whose signed attributes are ready to be signed.
#[derive(Debug)]
pub struct PreparedSignature {
    signed_attributes: SignedAttributes,
    to_be_signed: Vec<u8>,
    digest: DigestAlgorithm,
    key_type: KeyType,
    content: Option<Vec<u8>>,
    chain: Vec<Certificate>,
}

impl PreparedSignature {
    /// DER encoding of the signed attributes: the bytes the private key must sign
    /// (hashing them with the signature's digest algorithm).
    pub fn to_be_signed(&self) -> &[u8] {
        &self.to_be_signed
    }

    /// Builds the CAdES signature (DER `ContentInfo`) from the raw signature value.
    pub fn finish(self, signature: &[u8]) -> Result<Vec<u8>> {
        let leaf = &self.chain[0];
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: leaf.tbs_certificate.issuer.clone(),
                serial_number: leaf.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: self.digest.algorithm_identifier(),
            signed_attrs: Some(self.signed_attributes),
            signature_algorithm: cms_signature_algorithm(self.key_type, self.digest),
            signature: OctetString::new(signature)?,
            unsigned_attrs: None,
        };

        let certificates = self
            .chain
            .into_iter()
            .map(CertificateChoices::Certificate)
            .collect::<Vec<_>>();
        let econtent = self
            .content
            .map(|content| Any::new(Tag::OctetString, content))
            .transpose()?;

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::try_from(vec![self.digest.algorithm_identifier()])?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: oid::DATA,
                econtent,
            },
            certificates: Some(CertificateSet(SetOfVec::try_from(certificates)?)),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(vec![signer_info])?),
        };

        let content_info = ContentInfo {
            content_type: oid::SIGNED_DATA,
            content: Any::encode_from(&signed_data)?,
        };
        Ok(content_info.to_der()?)
    }
}

/// First phase of a signature: builds the signed attributes for `data`.
///
/// `chain` is the signer's certificate chain, leaf first.
pub fn prepare(
    data: &[u8],
    chain: &[Certificate],
    key_type: KeyType,
    params: &CadesParams,
) -> Result<PreparedSignature> {
    if data.is_empty() {
        return Err(Error::EmptyData);
    }
    let leaf = chain
        .first()
        .ok_or_else(|| Error::Certificate("falta el certificado del firmante".to_string()))?;
    let digest = params.digest;

    let mut attributes = vec![
        attribute(oid::CONTENT_TYPE, &oid::DATA)?,
        signing_time_attribute(params.signing_time)?,
        attribute(oid::MESSAGE_DIGEST, &OctetString::new(digest.digest(data))?)?,
        signing_certificate_v2(leaf, digest)?,
    ];
    if let Some(description) = &params.content_description {
        attributes.push(attribute(
            oid::CONTENT_HINT,
            &ContentHints {
                content_description: Some(description.clone()),
                content_type: oid::DATA,
            },
        )?);
    }
    if let Some(policy) = &params.policy {
        attributes.push(signature_policy(policy)?);
    }

    // SET OF: DER sorts the attributes by their encoding.
    let signed_attributes: SignedAttributes = SetOfVec::try_from(attributes)?;
    let to_be_signed = signed_attributes.to_der()?;

    Ok(PreparedSignature {
        signed_attributes,
        to_be_signed,
        digest,
        key_type,
        content: (params.mode == SignatureMode::Implicit).then(|| data.to_vec()),
        chain: chain.to_vec(),
    })
}

/// Signs `data` with `key`, producing a CAdES-BES (or EPES, with a policy) signature.
pub fn sign(data: &[u8], key: &dyn SigningKey, params: &CadesParams) -> Result<Vec<u8>> {
    let prepared = prepare(data, key.certificate_chain(), key.key_type(), params)?;
    let signature = key.sign_raw(params.digest, prepared.to_be_signed())?;
    prepared.finish(&signature)
}

/// Result of verifying one signer of a CAdES signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerReport {
    /// Signer certificate, when it is included in the signature.
    pub certificate: Option<CertificateInfo>,
    /// Digest algorithm.
    pub digest: Option<DigestAlgorithm>,
    /// Signing time from the `signingTime` attribute, seconds since the Unix epoch.
    pub signing_time: Option<i64>,
    /// Signature policy OID (CAdES-EPES).
    pub policy: Option<String>,
    /// Verification result.
    pub status: SignerStatus,
}

/// Outcome of the cryptographic verification of a signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerStatus {
    /// The signature is mathematically valid and matches the data.
    Valid,
    /// The data does not match the `messageDigest` attribute.
    DigestMismatch,
    /// The signature value is not valid for the signer's key.
    InvalidSignature,
    /// The signer's certificate is not included in the signature.
    CertificateNotFound,
    /// The signature uses something not supported yet.
    Unsupported(String),
}

/// Result of verifying a CAdES signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// The signed data is included in the signature (implicit).
    pub implicit: bool,
    /// One report per signer.
    pub signers: Vec<SignerReport>,
}

impl VerifyReport {
    /// Whether every signer is valid.
    pub fn is_valid(&self) -> bool {
        !self.signers.is_empty() && self.signers.iter().all(|s| s.status == SignerStatus::Valid)
    }
}

/// Verifies the integrity of a CAdES/CMS signature.
///
/// `data` is required for explicit (detached) signatures; for implicit ones the
/// embedded content is used when `data` is `None`. Certificate trust and
/// revocation are not checked.
pub fn verify(signature: &[u8], data: Option<&[u8]>) -> Result<VerifyReport> {
    let signed_data = parse_signed_data(signature)?;
    let embedded = embedded(&signed_data)?;
    let content = data
        .or(embedded.as_deref())
        .ok_or(Error::MissingSignedData)?;

    let certificates: Vec<&Certificate> = signed_data
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => Some(cert),
            _ => None,
        })
        .collect();

    let signers = signed_data
        .signer_infos
        .0
        .iter()
        .map(|signer| verify_signer(signer, &certificates, content))
        .collect::<Result<Vec<_>>>()?;

    Ok(VerifyReport {
        implicit: embedded.is_some(),
        signers,
    })
}

/// Content embedded in an implicit signature, if any.
pub fn embedded_content(signature: &[u8]) -> Result<Option<Vec<u8>>> {
    embedded(&parse_signed_data(signature)?)
}

fn parse_signed_data(signature: &[u8]) -> Result<SignedData> {
    let content_info =
        ContentInfo::from_der(signature).map_err(|e| Error::InvalidSignature(e.to_string()))?;
    if content_info.content_type != oid::SIGNED_DATA {
        return Err(Error::InvalidSignature(
            "no es una estructura SignedData".to_string(),
        ));
    }
    content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|e| Error::InvalidSignature(e.to_string()))
}

fn embedded(signed_data: &SignedData) -> Result<Option<Vec<u8>>> {
    signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .map(|any| {
            any.decode_as::<OctetString>()
                .map(|octets| octets.into_bytes())
                .map_err(|e| Error::InvalidSignature(e.to_string()))
        })
        .transpose()
}

fn verify_signer(
    signer: &SignerInfo,
    certificates: &[&Certificate],
    content: &[u8],
) -> Result<SignerReport> {
    let digest = DigestAlgorithm::from_oid(&signer.digest_alg.oid);
    let certificate = match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(id) => certificates.iter().copied().find(|cert| {
            cert.tbs_certificate.issuer == id.issuer
                && cert.tbs_certificate.serial_number == id.serial_number
        }),
        SignerIdentifier::SubjectKeyIdentifier(_) => None,
    };

    let mut report = SignerReport {
        certificate: certificate
            .map(|cert| CertificateInfo::from_certificate(cert, &crate::cert::to_der(cert)?))
            .transpose()?,
        digest,
        signing_time: None,
        policy: None,
        status: SignerStatus::Valid,
    };

    let Some(digest) = digest else {
        report.status = SignerStatus::Unsupported(signer.digest_alg.oid.to_string());
        return Ok(report);
    };

    let to_be_signed = match &signer.signed_attrs {
        Some(attributes) => {
            for attr in attributes.iter() {
                let Some(value) = attr.values.get(0) else {
                    continue;
                };
                match attr.oid {
                    oid::MESSAGE_DIGEST => {
                        let expected = value
                            .decode_as::<OctetString>()
                            .map_err(|e| Error::InvalidSignature(e.to_string()))?;
                        if expected.as_bytes() != digest.digest(content) {
                            report.status = SignerStatus::DigestMismatch;
                        }
                    }
                    oid::SIGNING_TIME => {
                        report.signing_time = decode_any::<Time>(value).map(|time| {
                            i64::try_from(time.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
                        });
                    }
                    oid::SIGNATURE_POLICY_ID => {
                        report.policy = decode_any::<SignaturePolicyId>(value)
                            .map(|policy| policy.sig_policy_id.to_string());
                    }
                    _ => {}
                }
            }
            attributes.to_der()?
        }
        None => content.to_vec(),
    };
    if report.status != SignerStatus::Valid {
        return Ok(report);
    }

    let Some(certificate) = certificate else {
        report.status = SignerStatus::CertificateNotFound;
        return Ok(report);
    };
    // `sha256WithRSAEncryption` and friends fix the digest; `rsaEncryption` uses the
    // SignerInfo digest algorithm.
    let signature_digest =
        digest_of_signature_algorithm(&signer.signature_algorithm.oid).unwrap_or(digest);
    report.status = check_signature(
        certificate,
        signature_digest,
        &to_be_signed,
        signer.signature.as_bytes(),
    );
    Ok(report)
}

fn check_signature(
    certificate: &Certificate,
    digest: DigestAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> SignerStatus {
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let Some(key_type) = CertificateInfo::from_certificate(certificate, &[])
        .ok()
        .and_then(|info| info.key_type)
    else {
        return SignerStatus::Unsupported(spki.algorithm.oid.to_string());
    };
    let hash = digest.digest(message);
    let public_key = spki.subject_public_key.raw_bytes();

    let valid = match key_type {
        KeyType::Rsa => spki
            .to_der()
            .ok()
            .and_then(|der| RsaPublicKey::from_public_key_der(&der).ok())
            .is_some_and(|key| {
                let padding = match digest {
                    DigestAlgorithm::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
                    DigestAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
                    DigestAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
                    DigestAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
                };
                key.verify(padding, &hash, signature).is_ok()
            }),
        KeyType::EcP256 => {
            match (
                p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key),
                p256::ecdsa::Signature::from_der(signature),
            ) {
                (Ok(key), Ok(signature)) => key.verify_prehash(&hash, &signature).is_ok(),
                _ => false,
            }
        }
        KeyType::EcP384 => {
            match (
                p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key),
                p384::ecdsa::Signature::from_der(signature),
            ) {
                (Ok(key), Ok(signature)) => key.verify_prehash(&hash, &signature).is_ok(),
                _ => false,
            }
        }
    };
    if valid {
        SignerStatus::Valid
    } else {
        SignerStatus::InvalidSignature
    }
}

fn attribute(oid: ObjectIdentifier, value: &impl Encode) -> Result<Attribute> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![Any::from_der(&value.to_der()?)?])?,
    })
}

/// Decodes an `ANY` value as `T` (also works for CHOICE types).
fn decode_any<T: for<'a> Decode<'a>>(value: &Any) -> Option<T> {
    T::from_der(&value.to_der().ok()?).ok()
}

fn signing_time_attribute(unix_seconds: i64) -> Result<Attribute> {
    let since_epoch = Duration::from_secs(
        u64::try_from(unix_seconds).map_err(|_| Error::InvalidTime(unix_seconds))?,
    );
    // RFC 5652: UTCTime until 2049, GeneralizedTime from 2050 on.
    match UtcTime::from_unix_duration(since_epoch) {
        Ok(time) => attribute(oid::SIGNING_TIME, &time),
        Err(_) => attribute(
            oid::SIGNING_TIME,
            &GeneralizedTime::from_unix_duration(since_epoch)
                .map_err(|_| Error::InvalidTime(unix_seconds))?,
        ),
    }
}

/// `SigningCertificateV2` (RFC 5035) with the hash and issuer/serial of `cert`.
fn signing_certificate_v2(cert: &Certificate, digest: DigestAlgorithm) -> Result<Attribute> {
    let cert_der = cert.to_der()?;
    let id = EssCertIdV2 {
        // DER omits the DEFAULT value (SHA-256).
        hash_algorithm: (digest != DigestAlgorithm::Sha256).then(|| digest.algorithm_identifier()),
        cert_hash: OctetString::new(digest.digest(&cert_der))?,
        issuer_serial: Some(IssuerSerial {
            issuer: vec![GeneralName::DirectoryName(
                cert.tbs_certificate.issuer.clone(),
            )],
            serial_number: cert.tbs_certificate.serial_number.clone(),
        }),
    };
    attribute(
        oid::SIGNING_CERTIFICATE_V2,
        &SigningCertificateV2 { certs: vec![id] },
    )
}

fn signature_policy(policy: &SignaturePolicy) -> Result<Attribute> {
    let qualifiers = policy
        .qualifier
        .as_ref()
        .map(|uri| -> Result<_> {
            Ok(vec![SigPolicyQualifierInfo {
                sig_policy_qualifier_id: oid::SPQ_ETS_URI,
                sig_qualifier: Any::encode_from(&Ia5String::new(uri)?)?,
            }])
        })
        .transpose()?;
    attribute(
        oid::SIGNATURE_POLICY_ID,
        &SignaturePolicyId {
            sig_policy_id: policy.oid()?,
            sig_policy_hash: OtherHashAlgAndValue {
                hash_algorithm: policy.hash_algorithm.algorithm_identifier(),
                hash_value: OctetString::new(policy.hash()?)?,
            },
            sig_policy_qualifiers: qualifiers,
        },
    )
}

/// `ContentHints` (RFC 2634).
#[derive(Debug, Sequence)]
struct ContentHints {
    #[asn1(optional = "true")]
    content_description: Option<String>,
    content_type: ObjectIdentifier,
}

/// `SigningCertificateV2` (RFC 5035), without policies.
#[derive(Debug, Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}

/// `ESSCertIDv2` (RFC 5035).
#[derive(Debug, Sequence)]
struct EssCertIdV2 {
    #[asn1(optional = "true")]
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    #[asn1(optional = "true")]
    issuer_serial: Option<IssuerSerial>,
}

/// `IssuerSerial` (RFC 5035).
#[derive(Debug, Sequence)]
struct IssuerSerial {
    issuer: Vec<GeneralName>,
    serial_number: SerialNumber,
}

/// `SignaturePolicyId` (RFC 5126).
#[derive(Debug, Sequence)]
struct SignaturePolicyId {
    sig_policy_id: ObjectIdentifier,
    sig_policy_hash: OtherHashAlgAndValue,
    #[asn1(optional = "true")]
    sig_policy_qualifiers: Option<Vec<SigPolicyQualifierInfo>>,
}

/// `OtherHashAlgAndValue` (RFC 5126).
#[derive(Debug, Sequence)]
struct OtherHashAlgAndValue {
    hash_algorithm: AlgorithmIdentifierOwned,
    hash_value: OctetString,
}

/// `SigPolicyQualifierInfo` (RFC 5126).
#[derive(Debug, Sequence)]
struct SigPolicyQualifierInfo {
    sig_policy_qualifier_id: ObjectIdentifier,
    sig_qualifier: Any,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{format::SignatureFormat, keystore::tests::load, policy::PolicyPreset};

    const DATA: &[u8] = b"Hola autofirma-rs\n";
    // 2026-10-15T12:00:00Z
    const SIGNING_TIME: i64 = 1_792_065_600;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/data/cades/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn params(digest: DigestAlgorithm, mode: SignatureMode, policy: bool) -> CadesParams {
        CadesParams {
            digest,
            mode,
            policy: policy.then(|| PolicyPreset::Age19.policy(SignatureFormat::Cades)),
            signing_time: SIGNING_TIME,
            content_description: Some("Texto plano".to_string()),
        }
    }

    #[test]
    fn sign_and_verify_every_combination() {
        for keystore in ["rsa.p12", "ec.p12"] {
            let key = &load(keystore)[0];
            for digest in [
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
            ] {
                for mode in [SignatureMode::Explicit, SignatureMode::Implicit] {
                    for policy in [false, true] {
                        let signature = sign(DATA, key, &params(digest, mode, policy)).unwrap();
                        let data = (mode == SignatureMode::Explicit).then_some(DATA);
                        let report = verify(&signature, data).unwrap();
                        assert!(
                            report.is_valid(),
                            "{keystore} {digest:?} {mode:?}: {report:?}"
                        );
                        assert_eq!(report.implicit, mode == SignatureMode::Implicit);
                        let signer = &report.signers[0];
                        assert_eq!(signer.digest, Some(digest));
                        assert_eq!(signer.signing_time, Some(SIGNING_TIME));
                        assert_eq!(
                            signer.policy.as_deref(),
                            policy.then_some("2.16.724.1.3.1.1.2.1.9")
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn detects_tampered_data() {
        let key = &load("rsa.p12")[0];
        let signature = sign(
            DATA,
            key,
            &params(DigestAlgorithm::Sha512, SignatureMode::Explicit, false),
        )
        .unwrap();
        let report = verify(&signature, Some(b"otra cosa")).unwrap();
        assert_eq!(report.signers[0].status, SignerStatus::DigestMismatch);
        assert!(matches!(
            verify(&signature, None),
            Err(Error::MissingSignedData)
        ));
    }

    #[test]
    fn implicit_signature_embeds_content() {
        let key = &load("ec.p12")[0];
        let signature = sign(
            DATA,
            key,
            &params(DigestAlgorithm::Sha256, SignatureMode::Implicit, false),
        )
        .unwrap();
        assert_eq!(embedded_content(&signature).unwrap().as_deref(), Some(DATA));
    }

    #[test]
    fn attributes_match_autofirma() {
        // Same attribute set as tests/data/cades/autofirma-implicit-age-rsa.csig.
        let key = &load("rsa.p12")[0];
        let prepared = prepare(
            DATA,
            key.certificate_chain(),
            key.key_type(),
            &params(DigestAlgorithm::Sha512, SignatureMode::Implicit, true),
        )
        .unwrap();
        let oids: Vec<_> = prepared.signed_attributes.iter().map(|a| a.oid).collect();
        for expected in [
            oid::CONTENT_TYPE,
            oid::SIGNING_TIME,
            oid::CONTENT_HINT,
            oid::MESSAGE_DIGEST,
            oid::SIGNATURE_POLICY_ID,
            oid::SIGNING_CERTIFICATE_V2,
        ] {
            assert!(oids.contains(&expected), "missing {expected}");
        }
        assert_eq!(oids.len(), 6);

        let reference = parse_signed_data(&fixture("autofirma-implicit-age-rsa.csig")).unwrap();
        let reference_attrs = reference
            .signer_infos
            .0
            .get(0)
            .unwrap()
            .signed_attrs
            .as_ref()
            .unwrap();
        let get = |attrs: &SignedAttributes, oid| {
            attrs
                .iter()
                .find(|a| a.oid == oid)
                .unwrap()
                .to_der()
                .unwrap()
        };
        // Deterministic attributes are byte for byte identical to AutoFirma's.
        for oid in [
            oid::CONTENT_TYPE,
            oid::CONTENT_HINT,
            oid::MESSAGE_DIGEST,
            oid::SIGNATURE_POLICY_ID,
            oid::SIGNING_CERTIFICATE_V2,
        ] {
            assert_eq!(
                get(&prepared.signed_attributes, oid),
                get(reference_attrs, oid),
                "attribute {oid} differs from AutoFirma"
            );
        }
    }

    #[test]
    fn verifies_autofirma_signatures() {
        for (name, data) in [
            ("autofirma-explicit-rsa.csig", Some(fixture("doc.txt"))),
            ("autofirma-explicit-ec.csig", Some(fixture("doc.txt"))),
            ("autofirma-implicit-age-rsa.csig", None),
        ] {
            let report = verify(&fixture(name), data.as_deref()).unwrap();
            assert!(report.is_valid(), "{name}: {report:?}");
            let signer = &report.signers[0];
            assert_eq!(signer.digest, Some(DigestAlgorithm::Sha512));
            assert!(signer.certificate.is_some());
        }
        let report = verify(&fixture("autofirma-implicit-age-rsa.csig"), None).unwrap();
        assert_eq!(
            report.signers[0].policy.as_deref(),
            Some("2.16.724.1.3.1.1.2.1.9")
        );
    }
}
