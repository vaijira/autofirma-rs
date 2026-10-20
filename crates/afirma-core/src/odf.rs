//! OpenDocument (ODF) signatures, as AutoFirma's `AOODFSigner` makes them: an
//! XMLDSig signature in `META-INF/documentsignatures.xml` with a reference to
//! every file of the package manifest, `mimetype` and the manifest itself
//! (ODF 1.2 / OpenOffice 3.2 signatures), plus a signed `dc:date`.
//!
//! Unlike AutoFirma, which always uses SHA-1 and RSA, the references and the
//! signature use the digest algorithm of the parameters, with RSA or ECDSA
//! keys; the `mimetype` part stays first and uncompressed. A co-signature is
//! one more signature in the same file; ODF has no counter-signatures.

use std::cell::RefCell;

use bergshamra_c14n::C14nMode;
use bergshamra_xml::uppsala;
use der::Encode;
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::{
    algorithm::KeyType,
    cert::rfc2253,
    digest::DigestAlgorithm,
    error::{Error, Result},
    format::DataKind,
    keystore::SigningKey,
    package::{Package, PackageReport, percent_decode},
    random,
    time::DateTime,
    xades::{self, PreparedXades, Reference, reference::Transform},
    xml::{self, DSIG_NS, XmlText, base64, escape_text, signature_method_uri, uri},
};

/// Part with the document signatures.
pub const SIGNATURES_PATH: &str = "META-INF/documentsignatures.xml";
const MANIFEST_PATH: &str = "META-INF/manifest.xml";
/// Namespace of `document-signatures`.
const SIGNATURES_NS: &str = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";
/// Parts that are not signed: the signatures themselves and the ones of macros.
const UNSIGNED_PARTS: [&str; 4] = [
    "mimetype",
    SIGNATURES_PATH,
    "META-INF/macrosignatures.xml",
    "META-INF/packagesignatures.xml",
];
/// XML parts whose references are canonicalized, as AutoFirma does.
const CANONICALIZED_PARTS: [&str; 4] = ["content.xml", "meta.xml", "styles.xml", "settings.xml"];

/// Parameters of an ODF signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OdfParams {
    /// Digest algorithm of the references and of the signature.
    pub digest: DigestAlgorithm,
    /// Signing time, seconds since the Unix epoch.
    pub signing_time: i64,
    /// Local time offset from UTC in minutes, for `dc:date`.
    pub utc_offset_minutes: i32,
}

impl OdfParams {
    /// SHA-512, AutoFirma's default algorithm.
    pub fn new(signing_time: i64) -> Self {
        OdfParams {
            digest: DigestAlgorithm::Sha512,
            signing_time,
            utc_offset_minutes: 0,
        }
    }
}

/// Whether `data` is an ODF document with signatures.
pub fn is_signed(data: &[u8]) -> bool {
    DataKind::detect(data) == DataKind::Odf
        && Package::open(data).is_ok_and(|package| package.has(SIGNATURES_PATH))
}

/// Resolves package-relative URIs to the parts of `package`.
fn resolver<'a>(package: &'a RefCell<Package<'_>>) -> impl Fn(&str) -> Result<Vec<u8>> + 'a {
    move |uri: &str| {
        let name = percent_decode(uri.trim_start_matches("./"));
        package.borrow_mut().read(&name)
    }
}

/// A signature of an ODF document that waits for the private key operation.
#[derive(Debug, Clone)]
pub struct PreparedOdf {
    document: Vec<u8>,
    signatures: PreparedXades,
}

impl PreparedOdf {
    /// Canonical `SignedInfo`: the bytes the private key must sign.
    pub fn to_be_signed(&self) -> &[u8] {
        self.signatures.to_be_signed()
    }

    /// The signed document, from the raw signature value.
    pub fn finish(self, signature: &[u8]) -> Result<Vec<u8>> {
        let signatures = self.signatures.finish(signature)?;
        Package::open(&self.document)?.rewrite(&[(SIGNATURES_PATH.to_string(), signatures)])
    }
}

/// First phase of an ODF signature (or co-signature, if the document is signed).
pub fn prepare(
    data: &[u8],
    chain: &[Certificate],
    key_type: KeyType,
    params: &OdfParams,
) -> Result<PreparedOdf> {
    if DataKind::detect(data) != DataKind::Odf {
        return Err(Error::InvalidPackage(
            "no es un documento OpenDocument".to_string(),
        ));
    }
    let leaf = chain
        .first()
        .ok_or_else(|| Error::Certificate("falta el certificado del firmante".to_string()))?;
    let mut package = Package::open(data)?;

    // A reference per file of the manifest, plus mimetype and the manifest.
    let manifest = XmlText::decode(&package.read(MANIFEST_PATH)?)?;
    let entries: Vec<String> = {
        let doc = uppsala::parse(&manifest.text).map_err(|e| Error::InvalidXml(e.to_string()))?;
        doc.descendants(doc.root())
            .into_iter()
            .filter(|&node| {
                doc.element(node)
                    .is_some_and(|e| e.name.local_name == "file-entry")
            })
            .filter_map(|node| doc.get_attribute(node, "full-path").map(str::to_string))
            .collect()
    };
    let c14n = || vec![Transform::C14n(C14nMode::Inclusive, Vec::new())];
    let mut references = Vec::new();
    if package.has("mimetype") {
        references.push(Reference {
            id: None,
            type_uri: None,
            uri: "mimetype".to_string(),
            transforms: Vec::new(),
        });
    }
    references.push(Reference {
        id: None,
        type_uri: None,
        uri: MANIFEST_PATH.to_string(),
        transforms: c14n(),
    });
    for path in entries {
        if path.ends_with('/') || path == SIGNATURES_PATH || !package.has(&path) {
            continue;
        }
        references.push(Reference {
            id: None,
            type_uri: None,
            transforms: if CANONICALIZED_PARTS.contains(&path.as_str()) {
                c14n()
            } else {
                Vec::new()
            },
            uri: xades::uri_path(&path),
        });
    }

    let id = random::uuid()?;
    let signature_id = format!("ID_{id}");
    let property_id = format!("ID_{id}-date");
    references.push(Reference {
        id: None,
        type_uri: None,
        uri: format!("#{property_id}"),
        transforms: Vec::new(),
    });

    // The signature, in the default XMLDSig namespace like OpenOffice's.
    let mut signature = format!(
        r#"<Signature xmlns="{DSIG_NS}" Id="{signature_id}"><SignedInfo><CanonicalizationMethod Algorithm="{}"/><SignatureMethod Algorithm="{}"/>"#,
        uri::C14N,
        signature_method_uri(key_type, params.digest)
    );
    let digest_slots = xades::write_references(&mut signature, "", &references, params.digest);
    signature.push_str(&format!(
        r#"</SignedInfo><SignatureValue Id="{signature_id}-SignatureValue">"#
    ));
    let value_slot = signature.len();
    let time = DateTime::from_unix(params.signing_time, params.utc_offset_minutes);
    signature.push_str(&format!(
        "</SignatureValue><KeyInfo><X509Data><X509SubjectName>{}</X509SubjectName>\
         <X509Certificate>{}</X509Certificate></X509Data></KeyInfo>\
         <Object><SignatureProperties><SignatureProperty Id=\"{property_id}\" Target=\"#{signature_id}\">\
         <dc:date xmlns:dc=\"http://purl.org/dc/elements/1.1/\">{:04}-{:02}-{:02}T{:02}:{:02}:{:02}</dc:date>\
         </SignatureProperty></SignatureProperties></Object></Signature>",
        escape_text(&rfc2253(leaf.tbs_certificate().subject())),
        base64(&leaf.to_der()?),
        time.year,
        time.month,
        time.day,
        time.hour,
        time.minute,
        time.second,
    ));

    // In the signatures file, after the existing signatures.
    let (output, prefix, suffix) = if package.has(SIGNATURES_PATH) {
        let existing = XmlText::decode(&package.read(SIGNATURES_PATH)?)?;
        let doc = uppsala::parse(&existing.text).map_err(|e| Error::InvalidXml(e.to_string()))?;
        let root = doc
            .document_element()
            .ok_or_else(|| Error::InvalidXml("firmas sin elemento raíz".to_string()))?;
        let range = doc
            .node_range(root)
            .ok_or_else(|| Error::InvalidXml("no se localizan las firmas".to_string()))?;
        if existing.text[range.clone()].ends_with("/>") {
            let open = range.end - 2;
            let name = doc
                .element(root)
                .expect("element")
                .name
                .prefixed_name()
                .into_owned();
            (
                existing.clone(),
                format!("{}>", &existing.text[..open]),
                format!("</{name}>{}", &existing.text[range.end..]),
            )
        } else {
            let at = xml::end_tag_start(&existing.text, range)?;
            (
                existing.clone(),
                existing.text[..at].to_string(),
                existing.text[at..].to_string(),
            )
        }
    } else {
        (
            XmlText::utf8(),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?><document-signatures xmlns="{SIGNATURES_NS}">"#
            ),
            "</document-signatures>".to_string(),
        )
    };

    let offset = prefix.len();
    let package = RefCell::new(package);
    let resolve = resolver(&package);
    let signatures = xades::complete(
        format!("{prefix}{signature}{suffix}"),
        &signature_id,
        &references,
        digest_slots.into_iter().map(|slot| offset + slot).collect(),
        offset + value_slot,
        params.digest,
        key_type,
        output,
        Some(&resolve),
    )?;
    Ok(PreparedOdf {
        document: data.to_vec(),
        signatures,
    })
}

/// Signs an ODF document; if it is signed, the new signature is added (co-signature).
pub fn sign(data: &[u8], key: &dyn SigningKey, params: &OdfParams) -> Result<Vec<u8>> {
    let prepared = prepare(data, key.certificate_chain(), key.key_type(), params)?;
    let signature = key.sign_raw(params.digest, prepared.to_be_signed())?;
    prepared.finish(&signature)
}

/// Verifies the signatures of an ODF document. Certificate trust and
/// revocation are not checked.
pub fn verify(data: &[u8]) -> Result<PackageReport> {
    let mut package = Package::open(data)?;
    if !package.has(SIGNATURES_PATH) {
        return Err(Error::InvalidSignature(
            "el documento no está firmado".to_string(),
        ));
    }
    let signatures = package.read(SIGNATURES_PATH)?;
    let parts: Vec<String> = package
        .names()
        .iter()
        .filter(|name| !UNSIGNED_PARTS.contains(&name.as_str()))
        .cloned()
        .collect();
    let package = RefCell::new(package);
    let resolve = resolver(&package);
    let report = xades::verify_with(&signatures, Some(&resolve), false)?;
    let unsigned_parts = parts
        .into_iter()
        .filter(|part| {
            report
                .signatures
                .iter()
                .filter(|s| s.signer.depth == 0)
                .any(|signature| {
                    !signature
                        .uris
                        .iter()
                        .any(|uri| percent_decode(uri.trim_start_matches("./")) == *part)
                })
        })
        .collect();
    Ok(PackageReport {
        signatures: report,
        unsigned_parts,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{keystore::tests::load, package::tests::zip};

    const MANIFEST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
 <manifest:file-entry manifest:full-path="/" manifest:version="1.2" manifest:media-type="application/vnd.oasis.opendocument.text"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="Pictures/una imagen.png" manifest:media-type="image/png"/>
</manifest:manifest>"#;

    pub(crate) fn odt() -> Vec<u8> {
        zip(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text"),
            ("content.xml", b"<?xml version=\"1.0\"?>\n<office:document-content xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\"><!-- c --><office:body>Hola</office:body></office:document-content>"),
            ("Pictures/una imagen.png", b"\x89PNG..."),
            ("META-INF/manifest.xml", MANIFEST),
        ])
    }

    #[test]
    fn sign_cosign_and_verify() {
        let document = odt();
        assert!(!is_signed(&document));
        let rsa = &load("rsa.p12")[0];
        let ec = &load("ec.p12")[0];
        let signed = sign(&document, rsa, &OdfParams::new(1_792_428_983)).unwrap();
        assert!(is_signed(&signed));
        assert_eq!(DataKind::detect(&signed), DataKind::Odf);
        let report = verify(&signed).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.signatures.signatures.len(), 1);

        let cosigned = sign(
            &signed,
            ec,
            &OdfParams {
                digest: DigestAlgorithm::Sha256,
                ..OdfParams::new(1_792_428_983)
            },
        )
        .unwrap();
        let report = verify(&cosigned).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.signatures.signatures.len(), 2);

        // A part changed after signing.
        let mut package = Package::open(&cosigned).unwrap();
        let tampered = package
            .rewrite(&[("content.xml".to_string(), b"<x/>".to_vec())])
            .unwrap();
        assert!(!verify(&tampered).unwrap().is_valid());
        // A part added after signing.
        let mut package = Package::open(&cosigned).unwrap();
        let added = package
            .rewrite(&[("Scripts/macro.xml".to_string(), b"<x/>".to_vec())])
            .unwrap();
        let report = verify(&added).unwrap();
        assert_eq!(report.unsigned_parts, ["Scripts/macro.xml"]);
        assert!(!report.is_valid());
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/data/odf/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn verifies_and_cosigns_autofirma_documents() {
        // AutoFirma: RSA-SHA1 references to every file of the manifest.
        let signed = fixture("autofirma-rsa.odt");
        let report = verify(&signed).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(
            report.signatures.signatures[0].signer.digest,
            Some(DigestAlgorithm::Sha1)
        );

        let key = &load("ec.p12")[0];
        let cosigned = sign(&signed, key, &OdfParams::new(1_792_428_983)).unwrap();
        let report = verify(&cosigned).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.signatures.signatures.len(), 2);

        // A LibreOffice document: every part is signed.
        let signed = sign(&fixture("doc.odt"), key, &OdfParams::new(1_792_428_983)).unwrap();
        let report = verify(&signed).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert!(report.unsigned_parts.is_empty());
    }

    #[test]
    fn rejects_other_documents() {
        let key = &load("rsa.p12")[0];
        assert!(matches!(
            sign(b"hola", key, &OdfParams::new(0)),
            Err(Error::InvalidPackage(_))
        ));
        assert!(verify(&odt()).is_err());
    }
}
