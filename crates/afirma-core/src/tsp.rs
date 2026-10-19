//! RFC 3161 timestamps: requests, responses and token verification.
//!
//! Like the triphase client, this module does no I/O: it builds the request body
//! (`application/timestamp-query`) and reads the response
//! (`application/timestamp-reply`); the browser sends it with `fetch`. The
//! formats add the tokens themselves: CAdES-T and PAdES signature timestamps
//! (`cades::add_timestamps`), XAdES-T (`xades::add_timestamps`) and PDF document
//! timestamps (`pades::prepare_document_timestamp`).

use cms::content_info::ContentInfo;
use const_oid::ObjectIdentifier;
use der::{
    Decode, Encode, Sequence, Tag, Tagged,
    asn1::{Any, Int, OctetString},
};
use serde::{Deserialize, Serialize};
use spki::AlgorithmIdentifierOwned;

use crate::{
    asic,
    cades::{self, SignerStatus},
    digest::DigestAlgorithm,
    error::{Error, Result},
    format::DataKind,
    pades, random, xades,
};

/// Timestamp options (AutoFirma's `tsaURL`, `tsaPolicy`, `tsaHashAlgorithm`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampParams {
    /// URL of the timestamping authority.
    pub url: String,
    /// Policy OID requested from the TSA (`reqPolicy`). AutoFirma's default is
    /// `0.4.0.2023.1.1`, but many TSAs reject policies they do not know.
    pub policy: Option<String>,
    /// Digest algorithm of the message imprint (AutoFirma's default is SHA-512).
    pub digest: DigestAlgorithm,
}

/// `MessageImprint` (RFC 3161).
#[derive(Debug, Clone, Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

/// `TimeStampReq` (RFC 3161), without extensions.
#[derive(Debug, Sequence)]
struct TimeStampReq {
    version: u8,
    message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    nonce: Option<Int>,
    #[asn1(default = "Default::default")]
    cert_req: bool,
}

/// `PKIStatusInfo` (RFC 3161).
#[derive(Debug, Sequence)]
struct PkiStatusInfo {
    status: u32,
    #[asn1(optional = "true")]
    status_string: Option<Vec<String>>,
    #[asn1(optional = "true")]
    fail_info: Option<der::asn1::BitString>,
}

/// `TimeStampResp` (RFC 3161).
#[derive(Debug, Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    time_stamp_token: Option<ContentInfo>,
}

/// Body of a timestamp request for `imprint`, the digest of the data computed with `digest`.
///
/// The request asks for the TSA certificate in the token and carries a random nonce.
pub fn request(digest: DigestAlgorithm, imprint: &[u8], policy: Option<&str>) -> Result<Vec<u8>> {
    let policy = policy
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            ObjectIdentifier::new(p.strip_prefix("urn:oid:").unwrap_or(p))
                .map_err(|_| Error::Timestamp(format!("política no válida: {p}")))
        })
        .transpose()?;
    // A positive 64 bit nonce.
    let mut nonce = random::bytes::<8>()?;
    nonce[0] &= 0x7f;
    let request = TimeStampReq {
        version: 1,
        message_imprint: MessageImprint {
            hash_algorithm: digest.algorithm_identifier(),
            hashed_message: OctetString::new(imprint)?,
        },
        req_policy: policy,
        nonce: Some(Int::new(&nonce)?),
        cert_req: true,
    };
    Ok(request.to_der()?)
}

/// Reads a timestamp response and returns its token (a CMS `ContentInfo`, DER).
pub fn parse_response(response: &[u8]) -> Result<Vec<u8>> {
    let response = TimeStampResp::from_der(response)
        .map_err(|_| Error::Timestamp("la respuesta de la TSA no es válida".to_string()))?;
    // granted (0) or grantedWithMods (1).
    if response.status.status > 1 {
        let text = response
            .status
            .status_string
            .map(|strings| strings.join(" "))
            .unwrap_or_default();
        return Err(Error::Timestamp(format!(
            "la TSA ha rechazado la petición (estado {}) {text}",
            response.status.status
        )));
    }
    response
        .time_stamp_token
        .ok_or_else(|| Error::Timestamp("la respuesta no contiene el sello".to_string()))?
        .to_der()
        .map_err(Error::from)
}

/// Result of verifying a timestamp token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampReport {
    /// Time asserted by the TSA, seconds since the Unix epoch.
    pub time: Option<i64>,
    /// Common name of the TSA certificate.
    pub tsa: Option<String>,
    /// The token signature is valid and its imprint matches the timestamped data.
    pub status: SignerStatus,
}

/// Contents of a `TSTInfo` this crate uses.
#[derive(Debug)]
struct TstInfo {
    imprint: MessageImprint,
    time: Option<i64>,
}

fn tst_info(token: &[u8]) -> Result<TstInfo> {
    let invalid = || Error::Timestamp("el sello de tiempo no es válido".to_string());
    let content = cades::embedded_content(token)?.ok_or_else(invalid)?;
    let fields = Vec::<Any>::from_der(&content).map_err(|_| invalid())?;
    // version, policy, messageImprint, serialNumber, genTime, ...
    let imprint = fields
        .get(2)
        .and_then(|any| any.decode_as::<MessageImprint>().ok())
        .ok_or_else(invalid)?;
    let time = fields
        .get(4)
        .filter(|any| any.tag() == Tag::GeneralizedTime)
        .and_then(|any| parse_generalized_time(any.value()));
    Ok(TstInfo { imprint, time })
}

/// Verifies `token`: its CMS signature, and that it timestamps the data whose
/// digest `digest_of` computes (with the algorithm the token used).
pub fn verify_token(
    token: &[u8],
    digest_of: impl FnOnce(DigestAlgorithm) -> Result<Vec<u8>>,
) -> TimestampReport {
    let mut report = TimestampReport {
        time: None,
        tsa: None,
        status: SignerStatus::Valid,
    };
    let info = match tst_info(token) {
        Ok(info) => info,
        Err(e) => {
            report.status = SignerStatus::Unsupported(e.to_string());
            return report;
        }
    };
    report.time = info.time;
    match cades::verify(token, None) {
        Ok(cms) => {
            let signer = cms.signers.into_iter().next();
            report.tsa = signer
                .as_ref()
                .and_then(|s| s.certificate.as_ref())
                .map(|c| c.subject_cn.clone());
            if let Some(signer) = signer {
                report.status = signer.status;
            }
        }
        Err(e) => report.status = SignerStatus::Unsupported(e.to_string()),
    }
    if report.status != SignerStatus::Valid {
        return report;
    }
    let algorithm = DigestAlgorithm::from_oid(&info.imprint.hash_algorithm.oid);
    let expected = algorithm.map(digest_of);
    report.status = match expected {
        Some(Ok(expected)) if expected == info.imprint.hashed_message.as_bytes() => {
            SignerStatus::Valid
        }
        Some(Ok(_)) => SignerStatus::DigestMismatch,
        Some(Err(e)) => SignerStatus::Unsupported(e.to_string()),
        None => SignerStatus::Unsupported(info.imprint.hash_algorithm.oid.to_string()),
    };
    report
}

/// Checks that a token from `response` timestamps `imprint`; returns the token.
pub(crate) fn token_for(
    response: &[u8],
    digest: DigestAlgorithm,
    imprint: &[u8],
) -> Result<Vec<u8>> {
    let token = parse_response(response)?;
    let info = tst_info(&token)?;
    if info.imprint.hash_algorithm.oid != digest.oid()
        || info.imprint.hashed_message.as_bytes() != imprint
    {
        return Err(Error::Timestamp(
            "el sello de tiempo no corresponde a la firma".to_string(),
        ));
    }
    Ok(token)
}

/// Digests to timestamp for the signature timestamps of `signed`: a CAdES or
/// XAdES signature, a signed PDF (its last signature) or an ASiC-S container.
pub fn signature_imprints(signed: &[u8], digest: DigestAlgorithm) -> Result<Vec<Vec<u8>>> {
    match DataKind::detect(signed) {
        DataKind::CmsSignedData => cades::timestamp_imprints(signed, digest),
        DataKind::Xml => xades::timestamp_imprints(signed, digest),
        DataKind::Pdf => pades::timestamp_imprints(signed, digest),
        DataKind::Zip if asic::is_asic(signed) => {
            signature_imprints(&asic::open(signed)?.signature, digest)
        }
        _ => Err(Error::Timestamp(
            "solo se pueden sellar firmas CAdES, XAdES, PAdES y ASiC".to_string(),
        )),
    }
}

/// Adds the tokens of the TSA `responses` (one per imprint of
/// [`signature_imprints`]) to `signed`: CAdES-T, XAdES-T or PAdES signature
/// timestamps, also inside ASiC-S containers.
pub fn add_signature_timestamps(
    signed: &[u8],
    digest: DigestAlgorithm,
    responses: &[Vec<u8>],
) -> Result<Vec<u8>> {
    match DataKind::detect(signed) {
        DataKind::CmsSignedData => cades::add_timestamps(signed, digest, responses),
        DataKind::Xml => xades::add_timestamps(signed, digest, responses),
        DataKind::Pdf => pades::add_timestamps(signed, digest, responses),
        DataKind::Zip if asic::is_asic(signed) => {
            let container = asic::open(signed)?;
            container.repackage(&add_signature_timestamps(
                &container.signature,
                digest,
                responses,
            )?)
        }
        _ => Err(Error::Timestamp(
            "solo se pueden sellar firmas CAdES, XAdES, PAdES y ASiC".to_string(),
        )),
    }
}

/// `YYYYMMDDhhmmss[.fff]Z` (fractions allowed by RFC 3161, not by the `der` crate).
fn parse_generalized_time(value: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(value).ok()?.strip_suffix('Z')?;
    let text = text.split('.').next()?;
    if text.len() != 14 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |range: std::ops::Range<usize>| text[range].parse::<i64>().ok();
    let days = crate::time::days_from_civil(n(0..4)?, n(4..6)?, n(6..8)?);
    Some(days * 86_400 + n(8..10)? * 3600 + n(10..12)? * 60 + n(12..14)?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        algorithm::oid,
        cades::{AttributeOptions, prepare_digest},
        keystore::{SigningKey, tests::load},
    };

    /// `TSTInfo` written by the test TSA.
    #[derive(Sequence)]
    struct TestTstInfo {
        version: u8,
        policy: ObjectIdentifier,
        message_imprint: MessageImprint,
        serial_number: Int,
        gen_time: Any,
    }

    /// Answers `request` like a TSA, signing with the EC test key; the time has
    /// a fraction of a second, as many TSAs write it.
    pub fn tsa_response(request: &[u8], time: &str) -> Vec<u8> {
        let request = TimeStampReq::from_der(request).unwrap();
        let info = TestTstInfo {
            version: 1,
            policy: request
                .req_policy
                .unwrap_or(ObjectIdentifier::new_unwrap("1.2.3.4.1")),
            message_imprint: request.message_imprint,
            serial_number: Int::new(&[7]).unwrap(),
            gen_time: Any::new(Tag::GeneralizedTime, time.as_bytes()).unwrap(),
        }
        .to_der()
        .unwrap();
        let key = &load("ec.p12")[0];
        let prepared = prepare_digest(
            &DigestAlgorithm::Sha256.digest(&info),
            Some(info),
            key.certificate_chain(),
            key.key_type(),
            DigestAlgorithm::Sha256,
            AttributeOptions {
                content_type: Some(oid::TST_INFO),
                ..AttributeOptions::default()
            },
        )
        .unwrap();
        let signature = key
            .sign_raw(DigestAlgorithm::Sha256, prepared.to_be_signed())
            .unwrap();
        let token = ContentInfo::from_der(&prepared.finish(&signature).unwrap()).unwrap();
        TimeStampResp {
            status: PkiStatusInfo {
                status: 0,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: Some(token),
        }
        .to_der()
        .unwrap()
    }

    #[test]
    fn request_response_and_verification() {
        let imprint = DigestAlgorithm::Sha512.digest(b"firma");
        let request = request(DigestAlgorithm::Sha512, &imprint, Some("0.4.0.2023.1.1")).unwrap();
        let parsed = TimeStampReq::from_der(&request).unwrap();
        assert!(parsed.cert_req);
        assert_eq!(parsed.req_policy.unwrap().to_string(), "0.4.0.2023.1.1");

        let response = tsa_response(&request, "20261019165623.457Z");
        let token = token_for(&response, DigestAlgorithm::Sha512, &imprint).unwrap();
        assert!(token_for(&response, DigestAlgorithm::Sha512, b"otro").is_err());

        let report = verify_token(&token, |digest| Ok(digest.digest(b"firma")));
        assert_eq!(report.status, SignerStatus::Valid);
        assert_eq!(report.time, Some(1_792_428_983));
        assert_eq!(report.tsa.as_deref(), Some("Prueba EC P-256"));
        let report = verify_token(&token, |digest| Ok(digest.digest(b"otra")));
        assert_eq!(report.status, SignerStatus::DigestMismatch);
    }

    #[test]
    fn rejected_requests() {
        let rejection = TimeStampResp {
            status: PkiStatusInfo {
                status: 2,
                status_string: Some(vec!["policy not supported".to_string()]),
                fail_info: None,
            },
            time_stamp_token: None,
        }
        .to_der()
        .unwrap();
        assert!(matches!(
            parse_response(&rejection),
            Err(Error::Timestamp(msg)) if msg.contains("policy not supported")
        ));
        assert!(parse_response(b"<html>").is_err());
        assert!(request(DigestAlgorithm::Sha256, b"x", Some("no-oid")).is_err());
    }

    #[test]
    fn generalized_times() {
        assert_eq!(
            parse_generalized_time(b"20261019165623Z"),
            Some(1_792_428_983)
        );
        assert_eq!(parse_generalized_time(b"20261019165623"), None);
    }

    #[test]
    fn timestamps_cades_and_asic() {
        use crate::cades::{CadesParams, SignatureMode};

        let key = &load("rsa.p12")[0];
        let params = CadesParams {
            digest: DigestAlgorithm::Sha256,
            mode: SignatureMode::Implicit,
            policy: None,
            signing_time: 1_792_428_983,
            content_description: None,
        };
        let cades = cades::sign(b"datos", key, &params).unwrap();
        let container = asic::sign_cades(b"datos", None, key, &params).unwrap();
        for signed in [cades, container] {
            let imprints = signature_imprints(&signed, DigestAlgorithm::Sha256).unwrap();
            assert_eq!(imprints.len(), 1);
            let response = tsa_response(
                &request(DigestAlgorithm::Sha256, &imprints[0], None).unwrap(),
                "20261019165624Z",
            );
            let stamped =
                add_signature_timestamps(&signed, DigestAlgorithm::Sha256, &[response]).unwrap();
            let verification = crate::validation::verify(&stamped, None, None).unwrap();
            assert!(verification.is_valid(), "{verification:?}");
            let signer = match verification {
                crate::validation::Verification::Cades(report) => report.signers[0].clone(),
                crate::validation::Verification::Asic(report) => match *report.signature {
                    crate::validation::Verification::Cades(report) => report.signers[0].clone(),
                    other => panic!("{other:?}"),
                },
                other => panic!("{other:?}"),
            };
            assert_eq!(signer.timestamps.len(), 1);
            assert_eq!(signer.timestamps[0].status, SignerStatus::Valid);
            assert!(
                signature_imprints(&stamped, DigestAlgorithm::Sha256)
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(signature_imprints(b"hola", DigestAlgorithm::Sha256).is_err());
    }
}
