//! Verification of XMLDSig / XAdES signatures.

use bergshamra_c14n::C14nMode;
use bergshamra_xml::uppsala::{self, Document, NodeId};
use der::Decode;
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use super::reference::{self, External, Ids, Transform, inclusive_prefixes};
use crate::{
    algorithm::KeyType,
    cades::{SignerReport, SignerStatus, check_signature},
    cert::CertificateInfo,
    digest::DigestAlgorithm,
    error::{Error, Result},
    tsp::{self, TimestampReport},
    xml::{
        self, DSIG_NS, XADES_NS, XADES_OLD_NS, XmlText, decode_base64, digest_from_uri,
        signature_method_from_uri, uri,
    },
};

/// Result of verifying one `ds:Signature` of an XML document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XadesSignatureReport {
    /// `Id` of the `ds:Signature` element.
    pub id: Option<String>,
    /// The signature has signed XAdES properties; plain XMLDSig otherwise.
    pub xades: bool,
    /// Roles claimed by the signer (`SignerRole`).
    pub claimed_roles: Vec<String>,
    /// City where it was signed (`SignatureProductionPlace`).
    pub production_city: Option<String>,
    /// Verification of the signature.
    pub signer: SignerReport,
    /// URIs of the references of the signature and of its manifests, to know
    /// which parts of a package it covers.
    #[serde(skip)]
    pub(crate) uris: Vec<String>,
}

/// Result of verifying the XML signatures of a document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XadesVerifyReport {
    /// One report per `ds:Signature`, in document order.
    pub signatures: Vec<XadesSignatureReport>,
}

impl XadesVerifyReport {
    /// Whether there is at least one signature and every one is valid.
    pub fn is_valid(&self) -> bool {
        !self.signatures.is_empty()
            && self
                .signatures
                .iter()
                .all(|s| s.signer.status == SignerStatus::Valid)
    }
}

/// Verifies the integrity of every XML signature of `xml`.
///
/// `data` is the signed file of detached signatures whose reference points
/// outside the document (as in ASiC containers). Certificate trust and
/// revocation are not checked.
pub fn verify(xml: &[u8], data: Option<&[u8]>) -> Result<XadesVerifyReport> {
    let resolve = |_: &str| data.map(<[u8]>::to_vec).ok_or(Error::MissingSignedData);
    verify_with(xml, data.map(|_| &resolve as _), false)
}

/// Verifies the XML signatures of `xml`, resolving the references to data
/// outside the document with `external`. With `check_manifests`, the
/// references of the `ds:Manifest`s inside the signatures are checked too
/// (OOXML packages sign their parts through one).
pub(crate) fn verify_with(
    xml: &[u8],
    external: External<'_>,
    check_manifests: bool,
) -> Result<XadesVerifyReport> {
    let source = XmlText::decode(xml)?;
    let doc = uppsala::parse(&source.text).map_err(|e| Error::InvalidXml(e.to_string()))?;
    let ids = Ids::new(&doc);
    let signatures: Vec<NodeId> = doc
        .descendants(doc.root())
        .into_iter()
        .filter(|&node| xml::is_element(&doc, node, DSIG_NS, "Signature"))
        .collect();
    if signatures.is_empty() {
        return Err(Error::InvalidSignature(
            "el XML no contiene firmas".to_string(),
        ));
    }
    let signatures = signatures
        .into_iter()
        .map(|signature| {
            let mut report = verify_signature(&doc, &ids, signature, external, check_manifests)?;
            report.signer.depth = u32::try_from(
                doc.ancestors(signature)
                    .into_iter()
                    .filter(|&node| xml::is_element(&doc, node, DSIG_NS, "Signature"))
                    .count(),
            )
            .unwrap_or(u32::MAX);
            Ok(report)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(XadesVerifyReport { signatures })
}

fn invalid(message: &str) -> Error {
    Error::InvalidSignature(message.to_string())
}

/// Element `local` in any XAdES namespace, child of `id`.
fn xades_child(doc: &Document<'_>, id: NodeId, local: &str) -> Option<NodeId> {
    std::iter::once(XADES_NS)
        .chain(XADES_OLD_NS)
        .find_map(|ns| xml::child(doc, id, ns, local))
}

/// Descendants named `local` in any XAdES namespace.
fn xades_descendants(doc: &Document<'_>, id: NodeId, local: &str) -> Vec<NodeId> {
    std::iter::once(XADES_NS)
        .chain(XADES_OLD_NS)
        .flat_map(|ns| xml::descendants(doc, id, ns, local))
        .collect()
}

/// A verified reference.
struct CheckedReference {
    uri: String,
    type_uri: Option<String>,
    valid: bool,
}

/// Digest of a `ds:Reference` element, and the one it declares. `None` when it
/// uses something not supported (the reason in the error string).
fn check_reference(
    doc: &Document<'_>,
    ids: &Ids,
    signature: NodeId,
    reference: NodeId,
    external: External<'_>,
) -> Result<std::result::Result<CheckedReference, String>> {
    let uri = doc
        .get_attribute(reference, "URI")
        .unwrap_or_default()
        .to_string();
    let transforms = match xml::child(doc, reference, DSIG_NS, "Transforms") {
        Some(list) => xml::children(doc, list, DSIG_NS, "Transform")
            .into_iter()
            .map(|transform| Transform::parse(doc, transform))
            .collect::<Result<Vec<_>>>(),
        None => Ok(Vec::new()),
    };
    let algorithm = xml::child(doc, reference, DSIG_NS, "DigestMethod")
        .and_then(|m| doc.get_attribute(m, "Algorithm"))
        .unwrap_or_default();
    let (transforms, Some(algorithm)) = (transforms, digest_from_uri(algorithm)) else {
        return Ok(Err(algorithm.to_string()));
    };
    let transforms = match transforms {
        Ok(transforms) => transforms,
        Err(Error::Unsupported(what)) => return Ok(Err(what)),
        Err(e) => return Err(e),
    };
    let expected = xml::child(doc, reference, DSIG_NS, "DigestValue")
        .and_then(|value| decode_base64(&doc.text_content_deep(value)))
        .ok_or_else(|| invalid("DigestValue no válido"))?;
    let computed = reference::digest(doc, ids, signature, &uri, &transforms, algorithm, external)?;
    Ok(Ok(CheckedReference {
        valid: computed == expected,
        type_uri: doc.get_attribute(reference, "Type").map(str::to_string),
        uri,
    }))
}

fn verify_signature(
    doc: &Document<'_>,
    ids: &Ids,
    signature: NodeId,
    external: External<'_>,
    check_manifests: bool,
) -> Result<XadesSignatureReport> {
    let mut report = XadesSignatureReport {
        id: doc.get_attribute(signature, "Id").map(str::to_string),
        xades: false,
        claimed_roles: Vec::new(),
        production_city: None,
        signer: SignerReport {
            certificate: None,
            digest: None,
            signing_time: None,
            policy: None,
            status: SignerStatus::Valid,
            timestamps: Vec::new(),
            depth: 0,
        },
        uris: Vec::new(),
    };

    let signed_info = xml::child(doc, signature, DSIG_NS, "SignedInfo")
        .ok_or_else(|| invalid("falta SignedInfo"))?;
    let c14n = xml::child(doc, signed_info, DSIG_NS, "CanonicalizationMethod")
        .ok_or_else(|| invalid("falta CanonicalizationMethod"))?;
    let c14n_uri = doc.get_attribute(c14n, "Algorithm").unwrap_or_default();
    let Some(c14n_mode) = C14nMode::from_uri(c14n_uri) else {
        report.signer.status = SignerStatus::Unsupported(c14n_uri.to_string());
        return Ok(report);
    };
    let method = xml::child(doc, signed_info, DSIG_NS, "SignatureMethod")
        .and_then(|m| doc.get_attribute(m, "Algorithm"))
        .unwrap_or_default();
    let Some((rsa, digest)) = signature_method_from_uri(method) else {
        report.signer.status = SignerStatus::Unsupported(method.to_string());
        return Ok(report);
    };
    report.signer.digest = Some(digest);

    // References.
    let mut references = Vec::new();
    for reference in xml::children(doc, signed_info, DSIG_NS, "Reference") {
        match check_reference(doc, ids, signature, reference, external)? {
            Ok(checked) => references.push(checked),
            Err(unsupported) => {
                report.signer.status = SignerStatus::Unsupported(unsupported);
                return Ok(report);
            }
        }
    }
    // Manifests (OOXML): their references are checked like those of SignedInfo.
    if check_manifests {
        let manifests: Vec<NodeId> = xml::children(doc, signature, DSIG_NS, "Object")
            .into_iter()
            .flat_map(|object| xml::children(doc, object, DSIG_NS, "Manifest"))
            .collect();
        for manifest in manifests {
            for reference in xml::children(doc, manifest, DSIG_NS, "Reference") {
                match check_reference(doc, ids, signature, reference, external)? {
                    Ok(checked) => references.push(checked),
                    Err(unsupported) => {
                        report.signer.status = SignerStatus::Unsupported(unsupported);
                        return Ok(report);
                    }
                }
            }
        }
    }
    report.uris = references.iter().map(|r| r.uri.clone()).collect();
    if references.is_empty() {
        return Err(invalid("la firma no tiene referencias"));
    }

    // Certificates and XAdES properties. Only signed properties are trusted.
    let certificates: Vec<(Certificate, Vec<u8>)> = xml::child(doc, signature, DSIG_NS, "KeyInfo")
        .map(|key_info| xml::descendants(doc, key_info, DSIG_NS, "X509Certificate"))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|node| decode_base64(&doc.text_content_deep(node)))
        .filter_map(|der| Some((Certificate::from_der(&der).ok()?, der)))
        .collect();
    let qualifying = xml::children(doc, signature, DSIG_NS, "Object")
        .into_iter()
        .find_map(|object| xades_child(doc, object, "QualifyingProperties"));
    let signed_properties = qualifying
        .and_then(|q| xades_child(doc, q, "SignedProperties"))
        .filter(|&properties| {
            let id = doc.get_attribute(properties, "Id").unwrap_or_default();
            references.iter().any(|r| {
                r.valid
                    && (r.uri == format!("#{id}")
                        || (id.is_empty()
                            && r.type_uri.as_deref() == Some(uri::SIGNED_PROPERTIES_TYPE)))
            })
        });
    let mut signing_certificate_digests = Vec::new();
    if let Some(properties) = signed_properties {
        report.xades = true;
        report.signer.signing_time = xades_descendants(doc, properties, "SigningTime")
            .first()
            .and_then(|&node| crate::time::parse_xml_date_time(&xml::text(doc, node)));
        report.signer.policy = xades_descendants(doc, properties, "SigPolicyId")
            .first()
            .and_then(|&id| xades_child(doc, id, "Identifier"))
            .map(|node| {
                let identifier = xml::text(doc, node);
                identifier
                    .strip_prefix("urn:oid:")
                    .unwrap_or(&identifier)
                    .to_string()
            });
        report.claimed_roles = xades_descendants(doc, properties, "ClaimedRole")
            .into_iter()
            .map(|node| xml::text(doc, node))
            .collect();
        report.production_city = xades_descendants(doc, properties, "City")
            .first()
            .map(|&node| xml::text(doc, node));
        for cert in xades_descendants(doc, properties, "CertDigest") {
            let algorithm = xml::child(doc, cert, DSIG_NS, "DigestMethod")
                .and_then(|m| doc.get_attribute(m, "Algorithm"))
                .and_then(digest_from_uri);
            let value = xml::child(doc, cert, DSIG_NS, "DigestValue")
                .and_then(|v| decode_base64(&doc.text_content_deep(v)));
            if let (Some(algorithm), Some(value)) = (algorithm, value) {
                signing_certificate_digests.push((algorithm, value));
            }
        }
    }

    // The signer certificate: the one named by SigningCertificate, if any.
    let signer_certificate = if signing_certificate_digests.is_empty() {
        certificates.first()
    } else {
        certificates.iter().find(|(_, der)| {
            signing_certificate_digests
                .iter()
                .any(|(algorithm, value)| algorithm.digest(der) == *value)
        })
    };
    if let Some((cert, der)) = signer_certificate {
        report.signer.certificate = Some(CertificateInfo::from_certificate(cert, der)?);
    }

    // Unsigned properties: signature timestamps.
    if let Some(qualifying) = qualifying {
        report.signer.timestamps = xades_descendants(doc, qualifying, "SignatureTimeStamp")
            .into_iter()
            .map(|timestamp| verify_signature_timestamp(doc, signature, timestamp))
            .collect();
        report.signer.timestamps.sort_by_key(|t| t.time);
    }

    report.signer.status = if references.iter().any(|r| !r.valid) {
        SignerStatus::DigestMismatch
    } else if !signing_certificate_digests.is_empty() && signer_certificate.is_none() {
        SignerStatus::CertificateMismatch
    } else if let Some((cert, _)) = signer_certificate {
        let canonical = reference::canonicalize_element(
            doc,
            signed_info,
            c14n_mode,
            &inclusive_prefixes(doc, c14n),
        )?;
        let value = xml::child(doc, signature, DSIG_NS, "SignatureValue")
            .and_then(|v| decode_base64(&doc.text_content_deep(v)))
            .ok_or_else(|| invalid("SignatureValue no válido"))?;
        check_value(cert, rsa, digest, &canonical, &value)
    } else {
        SignerStatus::CertificateNotFound
    };
    Ok(report)
}

/// Checks an XMLDSig signature value (`r || s` for ECDSA).
fn check_value(
    cert: &Certificate,
    rsa: bool,
    digest: DigestAlgorithm,
    message: &[u8],
    value: &[u8],
) -> SignerStatus {
    let key_type = CertificateInfo::from_certificate(cert, &[])
        .ok()
        .and_then(|info| info.key_type);
    match key_type {
        Some(KeyType::Rsa) if rsa => check_signature(cert, digest, message, value),
        Some(key_type @ (KeyType::EcP256 | KeyType::EcP384)) if !rsa => {
            match xml::ecdsa_value_to_der(key_type, value) {
                Some(der) => check_signature(cert, digest, message, &der),
                None => SignerStatus::InvalidSignature,
            }
        }
        _ => SignerStatus::InvalidSignature,
    }
}

/// Verifies a `SignatureTimeStamp`: a token over the canonical `SignatureValue`.
fn verify_signature_timestamp(
    doc: &Document<'_>,
    signature: NodeId,
    timestamp: NodeId,
) -> TimestampReport {
    let method = xml::child(doc, timestamp, DSIG_NS, "CanonicalizationMethod");
    let mode = method
        .and_then(|m| doc.get_attribute(m, "Algorithm"))
        .map_or(Some(C14nMode::Inclusive), C14nMode::from_uri);
    let prefixes = method
        .map(|m| inclusive_prefixes(doc, m))
        .unwrap_or_default();
    let token = std::iter::once(XADES_NS)
        .chain(XADES_OLD_NS)
        .find_map(|ns| xml::child(doc, timestamp, ns, "EncapsulatedTimeStamp"))
        .and_then(|node| decode_base64(&doc.text_content_deep(node)));
    let (Some(mode), Some(token)) = (mode, token) else {
        return TimestampReport {
            time: None,
            tsa: None,
            status: SignerStatus::Unsupported("sello de tiempo XML".to_string()),
        };
    };
    tsp::verify_token(&token, |digest| {
        let value = xml::child(doc, signature, DSIG_NS, "SignatureValue")
            .ok_or_else(|| invalid("falta SignatureValue"))?;
        Ok(digest.digest(&reference::canonicalize_element(
            doc, value, mode, &prefixes,
        )?))
    })
}
