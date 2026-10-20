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
//!
//! Co-signatures ([`cosign`]) add a signer over the same content; counter-signatures
//! ([`countersign`]) sign the signature value of existing signers and go in their
//! `countersignature` unsigned attribute, as AutoFirma's `AOCAdESCoSigner` and
//! `AOCAdESCounterSigner` do.

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
    multisign::CounterSignTarget,
    policy::SignaturePolicy,
    tsp::{self, TimestampReport},
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
#[derive(Debug, Clone)]
pub struct PreparedSignature {
    signed_attributes: SignedAttributes,
    to_be_signed: Vec<u8>,
    digest: DigestAlgorithm,
    key_type: KeyType,
    content_type: ObjectIdentifier,
    content: Option<Vec<u8>>,
    chain: Vec<Certificate>,
}

impl PreparedSignature {
    /// DER encoding of the signed attributes: the bytes the private key must sign
    /// (hashing them with the signature's digest algorithm).
    pub fn to_be_signed(&self) -> &[u8] {
        &self.to_be_signed
    }

    /// `SignerInfo` with the raw signature value.
    fn signer_info(&self, signature: &[u8]) -> Result<SignerInfo> {
        let leaf = &self.chain[0];
        Ok(SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: leaf.tbs_certificate().issuer().clone(),
                serial_number: leaf.tbs_certificate().serial_number().clone(),
            }),
            digest_alg: self.digest.algorithm_identifier(),
            signed_attrs: Some(self.signed_attributes.clone()),
            signature_algorithm: cms_signature_algorithm(self.key_type, self.digest),
            signature: OctetString::new(signature)?,
            unsigned_attrs: None,
        })
    }

    /// Builds the CAdES signature (DER `ContentInfo`) from the raw signature value.
    pub fn finish(self, signature: &[u8]) -> Result<Vec<u8>> {
        let signer_info = self.signer_info(signature)?;

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
                econtent_type: self.content_type,
                econtent,
            },
            certificates: Some(CertificateSet(SetOfVec::try_from(certificates)?)),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(vec![signer_info])?),
        };

        encode_signed_data(&signed_data)
    }

    /// Upper bound of the DER size of the finished signature, used to reserve
    /// space for it before signing (PAdES).
    pub fn max_encoded_len(&self) -> Result<usize> {
        let leaf = &self.chain[0];
        let signature_len = match self.key_type {
            // Modulus size; the public key BIT STRING has a few bytes of overhead.
            KeyType::Rsa => leaf
                .tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .raw_bytes()
                .len(),
            // DER `ECDSA-Sig-Value` with two maximum length INTEGERs.
            KeyType::EcP256 => 72,
            KeyType::EcP384 => 104,
        };
        Ok(self.clone().finish(&vec![0xff; signature_len])?.len())
    }
}

/// Signed attributes to include, besides `contentType`, `messageDigest` and
/// `signingCertificateV2`, which are always present.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AttributeOptions<'a> {
    /// `signingTime`, seconds since the Unix epoch.
    pub signing_time: Option<i64>,
    /// `contentHint` description.
    pub content_description: Option<&'a str>,
    /// `signaturePolicyIdentifier` (EPES).
    pub policy: Option<&'a SignaturePolicy>,
    /// `contentType`, `id-data` when `None`.
    pub content_type: Option<ObjectIdentifier>,
    /// Counter-signature: no `contentType` (RFC 5652, 11.1) and a `contentHint`
    /// of `id-data` without description, as AutoFirma writes them.
    pub counter_signature: bool,
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
    prepare_digest(
        &params.digest.digest(data),
        (params.mode == SignatureMode::Implicit).then(|| data.to_vec()),
        chain,
        key_type,
        params.digest,
        AttributeOptions {
            signing_time: Some(params.signing_time),
            content_description: params.content_description.as_deref(),
            policy: params.policy.as_ref(),
            content_type: None,
            counter_signature: false,
        },
    )
}

/// Builds the signed attributes for content whose `digest` is `message_digest`.
/// `content` is embedded in the signature when present (implicit mode).
pub(crate) fn prepare_digest(
    message_digest: &[u8],
    content: Option<Vec<u8>>,
    chain: &[Certificate],
    key_type: KeyType,
    digest: DigestAlgorithm,
    options: AttributeOptions<'_>,
) -> Result<PreparedSignature> {
    let leaf = chain
        .first()
        .ok_or_else(|| Error::Certificate("falta el certificado del firmante".to_string()))?;

    let content_type = options.content_type.unwrap_or(oid::DATA);
    let mut attributes = vec![
        attribute(oid::MESSAGE_DIGEST, &OctetString::new(message_digest)?)?,
        signing_certificate_v2(leaf, digest)?,
    ];
    if !options.counter_signature {
        attributes.push(attribute(oid::CONTENT_TYPE, &content_type)?);
    }
    if let Some(signing_time) = options.signing_time {
        attributes.push(signing_time_attribute(signing_time)?);
    }
    let content_description = options
        .content_description
        .filter(|_| !options.counter_signature);
    if content_description.is_some() || options.counter_signature {
        attributes.push(attribute(
            oid::CONTENT_HINT,
            &ContentHints {
                content_description: content_description.map(str::to_string),
                content_type: oid::DATA,
            },
        )?);
    }
    if let Some(policy) = options.policy {
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
        content_type,
        content,
        chain: chain.to_vec(),
    })
}

/// Signs `data` with `key`, producing a CAdES-BES (or EPES, with a policy) signature.
pub fn sign(data: &[u8], key: &dyn SigningKey, params: &CadesParams) -> Result<Vec<u8>> {
    let prepared = prepare(data, key.certificate_chain(), key.key_type(), params)?;
    let signature = key.sign_raw(params.digest, prepared.to_be_signed())?;
    prepared.finish(&signature)
}

/// Unsigned attributes of long-term (archive) signatures, which a new signer would
/// invalidate (AutoFirma's `CAdESMultiUtil.UNSUPPORTED_ATTRIBUTES`).
const LONG_TERM_ATTRIBUTES: [ObjectIdentifier; 4] = [
    oid::ARCHIVE_TIMESTAMP,
    oid::ARCHIVE_TIMESTAMP_V2,
    oid::ARCHIVE_TIMESTAMP_V3,
    oid::LONG_TERM_VALIDATION,
];

/// Fails if some signer, counter-signers included, has long-term attributes.
fn check_long_term(signers: &[SignerInfo]) -> Result<()> {
    for signer in signers {
        for attr in signer.unsigned_attrs.iter().flat_map(|attrs| attrs.iter()) {
            if LONG_TERM_ATTRIBUTES.contains(&attr.oid) {
                return Err(Error::LongTermSignature);
            }
        }
        check_long_term(&counter_signers(signer))?;
    }
    Ok(())
}

/// Counter-signers of `signer` (its `countersignature` attributes).
fn counter_signers(signer: &SignerInfo) -> Vec<SignerInfo> {
    signer
        .unsigned_attrs
        .iter()
        .flat_map(|attrs| attrs.iter())
        .filter(|attr| attr.oid == oid::COUNTER_SIGNATURE)
        .flat_map(|attr| attr.values.iter())
        .filter_map(|value| value.decode_as::<SignerInfo>().ok())
        .collect()
}

/// Adds the certificates of `chain` that the signature does not have yet.
fn add_certificates(signed_data: &mut SignedData, chain: &[Certificate]) -> Result<()> {
    let mut certificates: Vec<CertificateChoices> = signed_data
        .certificates
        .iter()
        .flat_map(|set| set.0.iter().cloned())
        .collect();
    for cert in chain {
        let choice = CertificateChoices::Certificate(cert.clone());
        if !certificates.contains(&choice) {
            certificates.push(choice);
        }
    }
    signed_data.certificates = Some(CertificateSet(SetOfVec::try_from(certificates)?));
    Ok(())
}

fn encode_signed_data(signed_data: &SignedData) -> Result<Vec<u8>> {
    let content_info = ContentInfo {
        content_type: oid::SIGNED_DATA,
        content: Any::encode_from(signed_data)?,
    };
    Ok(content_info.to_der()?)
}

/// `messageDigest` of the first signer that used `digest`.
fn existing_message_digest(signers: &[SignerInfo], digest: DigestAlgorithm) -> Option<Vec<u8>> {
    signers
        .iter()
        .filter(|signer| DigestAlgorithm::from_oid(&signer.digest_alg.oid) == Some(digest))
        .flat_map(|signer| signer.signed_attrs.iter().flat_map(|attrs| attrs.iter()))
        .find(|attr| attr.oid == oid::MESSAGE_DIGEST)
        .and_then(|attr| attr.values.get(0))
        .and_then(|value| value.decode_as::<OctetString>().ok())
        .map(|octets| octets.as_bytes().to_vec())
}

/// Adds a signer to a CAdES signature (co-signature).
///
/// The new signer signs the same content as the existing ones: `data` when
/// given, else the content embedded in the signature, else the `messageDigest`
/// of an existing signer that used `params.digest` (explicit signatures signed
/// with another algorithm need `data`). With `data` and `params.mode` implicit,
/// the content is embedded if the signature did not have it.
pub fn cosign(
    signature: &[u8],
    data: Option<&[u8]>,
    key: &dyn SigningKey,
    params: &CadesParams,
) -> Result<Vec<u8>> {
    let mut signed_data = parse_signed_data(signature)?;
    let mut signers: Vec<SignerInfo> = signed_data.signer_infos.0.iter().cloned().collect();
    check_long_term(&signers)?;
    let embedded = embedded(&signed_data)?;
    let digest = params.digest;
    let message_digest = match data.or(embedded.as_deref()) {
        Some(content) => digest.digest(content),
        None => existing_message_digest(&signers, digest).ok_or(Error::MissingSignedData)?,
    };
    if let Some(data) = data
        && embedded.is_none()
        && params.mode == SignatureMode::Implicit
    {
        signed_data.encap_content_info.econtent = Some(Any::new(Tag::OctetString, data)?);
    }

    let chain = key.certificate_chain();
    let prepared = prepare_digest(
        &message_digest,
        None,
        chain,
        key.key_type(),
        digest,
        AttributeOptions {
            signing_time: Some(params.signing_time),
            content_description: params.content_description.as_deref(),
            policy: params.policy.as_ref(),
            content_type: Some(signed_data.encap_content_info.econtent_type),
            counter_signature: false,
        },
    )?;
    let value = key.sign_raw(digest, prepared.to_be_signed())?;
    signers.push(prepared.signer_info(&value)?);

    let mut digest_algorithms: Vec<AlgorithmIdentifierOwned> =
        signed_data.digest_algorithms.iter().cloned().collect();
    if !digest_algorithms.iter().any(|alg| alg.oid == digest.oid()) {
        digest_algorithms.push(digest.algorithm_identifier());
    }
    signed_data.digest_algorithms = SetOfVec::try_from(digest_algorithms)?;
    signed_data.signer_infos = SignerInfos(SetOfVec::try_from(signers)?);
    add_certificates(&mut signed_data, chain)?;
    encode_signed_data(&signed_data)
}

/// Counter-signs the signers of a CAdES signature chosen by `target`: every
/// signer and counter-signer ([`CounterSignTarget::Tree`]), or those without
/// counter-signatures ([`CounterSignTarget::Leafs`]).
pub fn countersign(
    signature: &[u8],
    target: CounterSignTarget,
    key: &dyn SigningKey,
    params: &CadesParams,
) -> Result<Vec<u8>> {
    let mut signed_data = parse_signed_data(signature)?;
    let signers: Vec<SignerInfo> = signed_data.signer_infos.0.iter().cloned().collect();
    check_long_term(&signers)?;
    let signers = signers
        .into_iter()
        .map(|signer| countersign_signer(signer, target, key, params))
        .collect::<Result<Vec<_>>>()?;
    signed_data.signer_infos = SignerInfos(SetOfVec::try_from(signers)?);
    add_certificates(&mut signed_data, key.certificate_chain())?;
    encode_signed_data(&signed_data)
}

/// Counter-signs `signer` and, recursively, its counter-signers.
fn countersign_signer(
    mut signer: SignerInfo,
    target: CounterSignTarget,
    key: &dyn SigningKey,
    params: &CadesParams,
) -> Result<SignerInfo> {
    let mut attributes: Vec<Attribute> = signer
        .unsigned_attrs
        .iter()
        .flat_map(|attrs| attrs.iter().cloned())
        .collect();
    let mut leaf = true;
    for attr in attributes
        .iter_mut()
        .filter(|attr| attr.oid == oid::COUNTER_SIGNATURE)
    {
        leaf = false;
        let values = attr
            .values
            .iter()
            .map(|value| match value.decode_as::<SignerInfo>() {
                Ok(inner) => Ok(Any::encode_from(&countersign_signer(
                    inner, target, key, params,
                )?)?),
                // Keep values that are not SignerInfos as they are.
                Err(_) => Ok(value.clone()),
            })
            .collect::<Result<Vec<_>>>()?;
        attr.values = SetOfVec::try_from(values)?;
    }

    if target == CounterSignTarget::Tree || leaf {
        let digest = params.digest;
        let prepared = prepare_digest(
            &digest.digest(signer.signature.as_bytes()),
            None,
            key.certificate_chain(),
            key.key_type(),
            digest,
            AttributeOptions {
                signing_time: Some(params.signing_time),
                content_description: None,
                policy: params.policy.as_ref(),
                content_type: None,
                counter_signature: true,
            },
        )?;
        let value = key.sign_raw(digest, prepared.to_be_signed())?;
        let counter_signer = Any::encode_from(&prepared.signer_info(&value)?)?;
        match attributes
            .iter_mut()
            .find(|attr| attr.oid == oid::COUNTER_SIGNATURE)
        {
            Some(attr) => {
                let mut values: Vec<Any> = attr.values.iter().cloned().collect();
                values.push(counter_signer);
                attr.values = SetOfVec::try_from(values)?;
            }
            None => attributes.push(Attribute {
                oid: oid::COUNTER_SIGNATURE,
                values: SetOfVec::try_from(vec![counter_signer])?,
            }),
        }
    }
    signer.unsigned_attrs = (!attributes.is_empty())
        .then(|| SetOfVec::try_from(attributes))
        .transpose()?;
    Ok(signer)
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
    /// Signature timestamps (CAdES-T, XAdES-T), oldest first.
    #[serde(default)]
    pub timestamps: Vec<TimestampReport>,
    /// `0` for signers, `1` for counter-signatures of a signer, `2` for
    /// counter-signatures of a counter-signature...
    #[serde(default)]
    pub depth: u32,
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
    /// The certificate named by the signed attributes (XAdES
    /// `SigningCertificate`) is not the one included in the signature.
    CertificateMismatch,
    /// The signature uses something not supported yet.
    Unsupported(String),
}

/// Result of verifying a CAdES signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// The signed data is included in the signature (implicit).
    pub implicit: bool,
    /// One report per signer, each followed by its counter-signatures (depth first).
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

    let mut signers = Vec::new();
    for signer in signed_data.signer_infos.0.iter() {
        verify_tree(signer, &certificates, content, 0, &mut signers)?;
    }

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

/// Signature timestamp tokens (`id-aa-signatureTimeStampToken`) of a signer, DER.
fn timestamp_tokens(signer: &SignerInfo) -> Vec<Vec<u8>> {
    signer
        .unsigned_attrs
        .iter()
        .flat_map(|attrs| attrs.iter())
        .filter(|attr| attr.oid == oid::SIGNATURE_TIMESTAMP_TOKEN)
        .flat_map(|attr| attr.values.iter())
        .filter_map(|value| value.to_der().ok())
        .collect()
}

/// Verifies the signature timestamps of a signer: tokens over its signature value.
fn signature_timestamps(signer: &SignerInfo) -> Vec<TimestampReport> {
    let value = signer.signature.as_bytes();
    let mut reports: Vec<TimestampReport> = timestamp_tokens(signer)
        .iter()
        .map(|token| tsp::verify_token(token, |digest| Ok(digest.digest(value))))
        .collect();
    reports.sort_by_key(|report| report.time);
    reports
}

/// Digests to timestamp for CAdES-T: the signature value of every signer that
/// has no signature timestamp yet, computed with `digest`.
pub fn timestamp_imprints(signature: &[u8], digest: DigestAlgorithm) -> Result<Vec<Vec<u8>>> {
    let signed_data = parse_signed_data(signature)?;
    Ok(signed_data
        .signer_infos
        .0
        .iter()
        .filter(|signer| timestamp_tokens(signer).is_empty())
        .map(|signer| digest.digest(signer.signature.as_bytes()))
        .collect())
}

/// Adds signature timestamps (CAdES-T) from TSA `responses` to the signers
/// they timestamp, matched by the imprint of each token.
pub fn add_timestamps(
    signature: &[u8],
    digest: DigestAlgorithm,
    responses: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let mut signed_data = parse_signed_data(signature)?;
    let mut signers: Vec<SignerInfo> = signed_data.signer_infos.0.iter().cloned().collect();
    let mut pending: Vec<&Vec<u8>> = responses.iter().collect();
    for signer in signers
        .iter_mut()
        .filter(|signer| timestamp_tokens(signer).is_empty())
    {
        let imprint = digest.digest(signer.signature.as_bytes());
        let Some(position) = pending
            .iter()
            .position(|response| tsp::token_for(response, digest, &imprint).is_ok())
        else {
            continue;
        };
        let token = tsp::token_for(pending.remove(position), digest, &imprint)?;
        let attribute = Attribute {
            oid: oid::SIGNATURE_TIMESTAMP_TOKEN,
            values: SetOfVec::try_from(vec![Any::from_der(&token)?])?,
        };
        let mut attributes: Vec<Attribute> = signer
            .unsigned_attrs
            .iter()
            .flat_map(|attrs| attrs.iter().cloned())
            .collect();
        attributes.push(attribute);
        signer.unsigned_attrs = Some(SetOfVec::try_from(attributes)?);
    }
    if let Some(response) = pending.first() {
        // Report why the response does not fit: rejection or a foreign token.
        tsp::parse_response(response)?;
        return Err(Error::Timestamp(
            "el sello de tiempo no corresponde a la firma".to_string(),
        ));
    }
    signed_data.signer_infos = SignerInfos(SetOfVec::try_from(signers)?);
    encode_signed_data(&signed_data)
}

fn embedded(signed_data: &SignedData) -> Result<Option<Vec<u8>>> {
    signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .map(|any| {
            any.decode_as::<OctetString>()
                .map(|octets| octets.into_bytes().into_vec())
                .map_err(|e| Error::InvalidSignature(e.to_string()))
        })
        .transpose()
}

/// Verifies `signer` over `content` and its counter-signers over its signature value.
fn verify_tree(
    signer: &SignerInfo,
    certificates: &[&Certificate],
    content: &[u8],
    depth: u32,
    reports: &mut Vec<SignerReport>,
) -> Result<()> {
    let mut report = verify_signer(signer, certificates, content)?;
    report.depth = depth;
    reports.push(report);
    for counter_signer in counter_signers(signer) {
        verify_tree(
            &counter_signer,
            certificates,
            signer.signature.as_bytes(),
            depth + 1,
            reports,
        )?;
    }
    Ok(())
}

fn verify_signer(
    signer: &SignerInfo,
    certificates: &[&Certificate],
    content: &[u8],
) -> Result<SignerReport> {
    let digest = DigestAlgorithm::from_oid(&signer.digest_alg.oid);
    let certificate = match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(id) => certificates.iter().copied().find(|cert| {
            *cert.tbs_certificate().issuer() == id.issuer
                && *cert.tbs_certificate().serial_number() == id.serial_number
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
        timestamps: signature_timestamps(signer),
        depth: 0,
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

/// Checks a PKCS#1 v1.5 (RSA) or DER ECDSA `signature` of `message` with the key of `certificate`.
pub(crate) fn check_signature(
    certificate: &Certificate,
    digest: DigestAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> SignerStatus {
    let spki = certificate.tbs_certificate().subject_public_key_info();
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
            .and_then(|der| RsaPublicKey::from_public_key_der(der.as_ref()).ok())
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
                cert.tbs_certificate().issuer().clone(),
            )],
            serial_number: cert.tbs_certificate().serial_number().clone(),
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

    #[test]
    fn cosign_explicit_and_implicit() {
        let rsa = &load("rsa.p12")[0];
        let ec = &load("ec.p12")[0];
        // Explicit, same algorithm: the messageDigest of the first signer is reused.
        let explicit = sign(
            DATA,
            rsa,
            &params(DigestAlgorithm::Sha512, SignatureMode::Explicit, false),
        )
        .unwrap();
        let cosigned = cosign(
            &explicit,
            None,
            ec,
            &params(DigestAlgorithm::Sha512, SignatureMode::Explicit, true),
        )
        .unwrap();
        let report = verify(&cosigned, Some(DATA)).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.signers.len(), 2);
        assert!(!report.implicit);
        // Another algorithm needs the data.
        assert!(matches!(
            cosign(
                &explicit,
                None,
                ec,
                &params(DigestAlgorithm::Sha256, SignatureMode::Explicit, false)
            ),
            Err(Error::MissingSignedData)
        ));
        let cosigned = cosign(
            &explicit,
            Some(DATA),
            ec,
            &params(DigestAlgorithm::Sha256, SignatureMode::Explicit, false),
        )
        .unwrap();
        let report = verify(&cosigned, Some(DATA)).unwrap();
        assert!(report.is_valid(), "{report:?}");
        // DER sorts the SignerInfos: the new one is not necessarily the last.
        assert!(
            report
                .signers
                .iter()
                .any(|s| s.digest == Some(DigestAlgorithm::Sha256))
        );
        let digests = parse_signed_data(&cosigned).unwrap().digest_algorithms;
        assert_eq!(digests.len(), 2);
        // With the data and implicit mode, the data is embedded.
        let cosigned = cosign(
            &explicit,
            Some(DATA),
            ec,
            &params(DigestAlgorithm::Sha256, SignatureMode::Implicit, false),
        )
        .unwrap();
        let report = verify(&cosigned, None).unwrap();
        assert!(report.is_valid() && report.implicit, "{report:?}");

        // Implicit: the embedded content is signed again.
        let implicit = sign(
            DATA,
            rsa,
            &params(DigestAlgorithm::Sha256, SignatureMode::Implicit, false),
        )
        .unwrap();
        let cosigned = cosign(
            &implicit,
            None,
            ec,
            &params(DigestAlgorithm::Sha384, SignatureMode::Explicit, false),
        )
        .unwrap();
        let report = verify(&cosigned, None).unwrap();
        assert!(report.is_valid() && report.implicit, "{report:?}");
        assert_eq!(report.signers.len(), 2);
        // The certificates of both signers, once each.
        let certificates = parse_signed_data(&cosigned).unwrap().certificates.unwrap();
        assert_eq!(certificates.0.len(), 3);
    }

    #[test]
    fn countersign_leafs_and_tree() {
        let rsa = &load("rsa.p12")[0];
        let ec = &load("ec.p12")[0];
        let explicit = sign(
            DATA,
            rsa,
            &params(DigestAlgorithm::Sha512, SignatureMode::Explicit, false),
        )
        .unwrap();
        let cosigned = cosign(
            &explicit,
            None,
            rsa,
            &params(DigestAlgorithm::Sha512, SignatureMode::Explicit, false),
        )
        .unwrap();

        let leafs = countersign(
            &cosigned,
            CounterSignTarget::Leafs,
            ec,
            &params(DigestAlgorithm::Sha256, SignatureMode::Explicit, false),
        )
        .unwrap();
        let report = verify(&leafs, Some(DATA)).unwrap();
        assert!(report.is_valid(), "{report:?}");
        let depths: Vec<u32> = report.signers.iter().map(|s| s.depth).collect();
        assert_eq!(depths, [0, 1, 0, 1]);

        let tree = countersign(
            &leafs,
            CounterSignTarget::Tree,
            rsa,
            &params(DigestAlgorithm::Sha512, SignatureMode::Explicit, true),
        )
        .unwrap();
        let report = verify(&tree, Some(DATA)).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.signers.len(), 8);
        assert_eq!(report.signers.iter().filter(|s| s.depth == 2).count(), 2);

        let again = countersign(
            &tree,
            CounterSignTarget::Leafs,
            ec,
            &params(DigestAlgorithm::Sha384, SignatureMode::Explicit, false),
        )
        .unwrap();
        let report = verify(&again, Some(DATA)).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.signers.len(), 12);

        // Counter-signature attributes: no contentType, a contentHint without description.
        let signed_data = parse_signed_data(&leafs).unwrap();
        let signer = signed_data.signer_infos.0.get(0).unwrap();
        let counter_signer = &counter_signers(signer)[0];
        let oids: Vec<_> = counter_signer
            .signed_attrs
            .as_ref()
            .unwrap()
            .iter()
            .map(|a| a.oid)
            .collect();
        assert!(!oids.contains(&oid::CONTENT_TYPE));
        let hint = counter_signer
            .signed_attrs
            .as_ref()
            .unwrap()
            .iter()
            .find(|a| a.oid == oid::CONTENT_HINT)
            .unwrap();
        assert_eq!(
            hint.values.get(0).unwrap().to_der().unwrap(),
            [
                0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01
            ]
        );

        // A tampered counter-signature is reported.
        let mut tampered = leafs.clone();
        let value = counter_signer.signature.as_bytes();
        let at = tampered
            .windows(value.len())
            .position(|w| w == value)
            .unwrap();
        tampered[at + 10] ^= 1;
        let report = verify(&tampered, Some(DATA)).unwrap();
        assert_eq!(report.signers[1].status, SignerStatus::InvalidSignature);
        assert!(!report.is_valid());
    }

    #[test]
    fn cosign_autofirma_signatures() {
        let key = &load("ec.p12")[0];
        for (name, data) in [
            ("autofirma-explicit-rsa.csig", Some(fixture("doc.txt"))),
            ("autofirma-implicit-age-rsa.csig", None),
        ] {
            let original = fixture(name);
            let cosigned = cosign(
                &original,
                None,
                key,
                &params(DigestAlgorithm::Sha512, SignatureMode::Explicit, false),
            )
            .unwrap();
            let report = verify(&cosigned, data.as_deref()).unwrap();
            assert!(report.is_valid(), "{name}: {report:?}");
            let countersigned = countersign(
                &original,
                CounterSignTarget::Tree,
                key,
                &params(DigestAlgorithm::Sha256, SignatureMode::Explicit, false),
            )
            .unwrap();
            let report = verify(&countersigned, data.as_deref()).unwrap();
            assert!(report.is_valid(), "{name}: {report:?}");
            assert_eq!(report.signers.len(), 2);
        }
    }

    #[test]
    fn verifies_autofirma_multisignatures() {
        // Co-signature of the AGE signature, then counter-signed (tree) with EC.
        let report = verify(&fixture("autofirma-cosign-rsa.csig"), None).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.signers.len(), 2);
        let countersigned = fixture("autofirma-countersign-ec.csig");
        let report = verify(&countersigned, None).unwrap();
        assert!(report.is_valid(), "{report:?}");
        let depths: Vec<u32> = report.signers.iter().map(|s| s.depth).collect();
        assert_eq!(depths, [0, 1, 0, 1]);

        // Our counter-signatures have the attributes of AutoFirma's.
        let reference = parse_signed_data(&countersigned).unwrap();
        let reference = &counter_signers(reference.signer_infos.0.get(0).unwrap())[0];
        let key = &load("ec.p12")[0];
        let ours = countersign(
            &fixture("autofirma-cosign-rsa.csig"),
            CounterSignTarget::Leafs,
            key,
            &params(DigestAlgorithm::Sha512, SignatureMode::Explicit, false),
        )
        .unwrap();
        let ours = parse_signed_data(&ours).unwrap();
        let ours = &counter_signers(ours.signer_infos.0.get(0).unwrap())[0];
        let oids = |signer: &SignerInfo| {
            let mut oids: Vec<String> = signer
                .signed_attrs
                .as_ref()
                .unwrap()
                .iter()
                .map(|a| a.oid.to_string())
                .collect();
            oids.sort();
            oids
        };
        assert_eq!(oids(ours), oids(reference));
        let hint = |signer: &SignerInfo| {
            signer
                .signed_attrs
                .as_ref()
                .unwrap()
                .iter()
                .find(|a| a.oid == oid::CONTENT_HINT)
                .unwrap()
                .to_der()
                .unwrap()
        };
        assert_eq!(hint(ours), hint(reference));
    }
}
