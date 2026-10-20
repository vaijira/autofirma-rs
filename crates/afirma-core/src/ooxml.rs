//! Office Open XML (OOXML: `.docx`, `.xlsx`, `.pptx`) signatures, as
//! AutoFirma's `AOOOXMLSigner` makes them (ECMA-376 Part 2, Digital Signatures):
//!
//! * the signature is a part of the package (`_xmlsignatures/sigN.xml`),
//!   related to the signature origin part, which `_rels/.rels` relates to the
//!   package;
//! * a `ds:Manifest` references the relationship parts (through the OPC
//!   relationship transform, leaving out the relationships that change when
//!   the document is saved: properties, thumbnail, signature origin) and the
//!   parts of the document (`word/`, `xl/`, `powerpoint/`...);
//! * Office's `SignatureInfoV1` properties, the signing time and XAdES-EPES
//!   signed properties with an implied policy.
//!
//! A co-signature is one more signature part; OOXML has no counter-signatures.

use std::cell::RefCell;

use bergshamra_c14n::C14nMode;
use bergshamra_xml::uppsala;
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::{
    algorithm::KeyType,
    digest::DigestAlgorithm,
    error::{Error, Result},
    format::DataKind,
    keystore::SigningKey,
    package::{Package, PackageReport, percent_decode},
    random,
    time::DateTime,
    xades::{
        self, PreparedXades, ProductionPlace, Reference, XadesParams,
        reference::{MDSSI_NS, Transform},
    },
    xml::{self, DSIG_NS, XADES_NS, XmlText, escape_attr, escape_text, signature_method_uri, uri},
};

const CONTENT_TYPES: &str = "[Content_Types].xml";
const ROOT_RELATIONSHIPS: &str = "_rels/.rels";
const RELATIONSHIPS_NS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const RELATIONSHIPS_CONTENT_TYPE: &str = "application/vnd.openxmlformats-package.relationships+xml";
const ORIGIN_RELATIONSHIP: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin";
const SIGNATURE_RELATIONSHIP: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature";
const ORIGIN_CONTENT_TYPE: &str = "application/vnd.openxmlformats-package.digital-signature-origin";
const SIGNATURE_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml";
const DEFAULT_ORIGIN: &str = "_xmlsignatures/origin.sigs";
/// Office's signature properties namespace.
const OFFICE_NS: &str = "http://schemas.microsoft.com/office/2006/digsig";
/// Folders with the parts of the document that are signed.
const CONTENT_DIRS: [&str; 4] = ["word/", "excel/", "xl/", "powerpoint/"];
/// Relationships that are not signed, since they change when the document is saved.
const EXCLUDED_RELATIONSHIPS: [&str; 6] = [
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties",
    "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
    ORIGIN_RELATIONSHIP,
    "http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/presProps",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/viewProps",
];

/// Parameters of an OOXML signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OoxmlParams {
    /// Digest algorithm of the references and of the signature.
    pub digest: DigestAlgorithm,
    /// Signing time, seconds since the Unix epoch.
    pub signing_time: i64,
    /// Local time offset from UTC in minutes, for the XAdES `SigningTime`.
    pub utc_offset_minutes: i32,
    /// Where the signature was made.
    pub production_place: ProductionPlace,
    /// Roles claimed by the signer.
    pub claimed_roles: Vec<String>,
    /// Purpose of the signature, shown by Office (`signatureComments`).
    pub comments: Option<String>,
}

impl OoxmlParams {
    /// SHA-512, AutoFirma's default algorithm.
    pub fn new(signing_time: i64) -> Self {
        OoxmlParams {
            digest: DigestAlgorithm::Sha512,
            signing_time,
            utc_offset_minutes: 0,
            production_place: ProductionPlace::default(),
            claimed_roles: Vec::new(),
            comments: None,
        }
    }
}

/// Whether `data` is an OOXML document with signatures.
pub fn is_signed(data: &[u8]) -> bool {
    DataKind::detect(data) == DataKind::Ooxml
        && Package::open(data).is_ok_and(|mut package| {
            signature_parts(&mut package).is_ok_and(|parts| !parts.is_empty())
        })
}

/// Name of a part from a relationship `target`, relative to the folder of the
/// part the relationships belong to (`""` for the package).
fn resolve_target(base_dir: &str, target: &str) -> String {
    let mut parts: Vec<&str> = if let Some(absolute) = target.strip_prefix('/') {
        absolute.split('/').collect()
    } else {
        base_dir
            .split('/')
            .filter(|p| !p.is_empty())
            .chain(target.split('/'))
            .collect()
    };
    let mut out: Vec<&str> = Vec::new();
    for part in parts.drain(..) {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            part => out.push(part),
        }
    }
    percent_decode(&out.join("/"))
}

/// Folder of a part name (`"a/b.xml"` → `"a"`).
fn folder(name: &str) -> &str {
    name.rfind('/').map_or("", |i| &name[..i])
}

/// Relationships part of a part (`a/b.xml` → `a/_rels/b.xml.rels`).
fn relationships_part(name: &str) -> String {
    match name.rfind('/') {
        Some(i) => format!("{}/_rels/{}.rels", &name[..i], &name[i + 1..]),
        None => format!("_rels/{name}.rels"),
    }
}

/// `(Id, Type, Target)` of the relationships of a relationships part.
fn relationships(xml: &[u8]) -> Result<Vec<(String, String, String)>> {
    let source = XmlText::decode(xml)?;
    let doc = uppsala::parse(&source.text).map_err(|e| Error::InvalidXml(e.to_string()))?;
    let root = doc
        .document_element()
        .ok_or_else(|| Error::InvalidXml("relaciones sin elemento raíz".to_string()))?;
    Ok(xml::children(&doc, root, RELATIONSHIPS_NS, "Relationship")
        .into_iter()
        .map(|node| {
            let get = |name| {
                doc.get_attribute(node, name)
                    .unwrap_or_default()
                    .to_string()
            };
            (get("Id"), get("Type"), get("Target"))
        })
        .collect())
}

/// The signature origin part, if the package has one.
fn origin_part(package: &mut Package<'_>) -> Result<Option<String>> {
    if !package.has(ROOT_RELATIONSHIPS) {
        return Ok(None);
    }
    Ok(relationships(&package.read(ROOT_RELATIONSHIPS)?)?
        .into_iter()
        .find(|(_, kind, _)| kind == ORIGIN_RELATIONSHIP)
        .map(|(_, _, target)| resolve_target("", &target)))
}

/// The signature parts of the package.
fn signature_parts(package: &mut Package<'_>) -> Result<Vec<String>> {
    let Some(origin) = origin_part(package)? else {
        return Ok(Vec::new());
    };
    let origin_relationships = relationships_part(&origin);
    if !package.has(&origin_relationships) {
        return Ok(Vec::new());
    }
    Ok(relationships(&package.read(&origin_relationships)?)?
        .into_iter()
        .filter(|(_, kind, _)| kind == SIGNATURE_RELATIONSHIP)
        .map(|(_, _, target)| resolve_target(folder(&origin), &target))
        .filter(|part| package.has(part))
        .collect())
}

/// Content types of the parts (`[Content_Types].xml`).
struct ContentTypes {
    defaults: Vec<(String, String)>,
    overrides: Vec<(String, String)>,
}

impl ContentTypes {
    fn parse(xml: &[u8]) -> Result<Self> {
        let source = XmlText::decode(xml)?;
        let doc = uppsala::parse(&source.text).map_err(|e| Error::InvalidXml(e.to_string()))?;
        let root = doc
            .document_element()
            .ok_or_else(|| Error::InvalidXml("tipos de contenido vacíos".to_string()))?;
        let mut types = ContentTypes {
            defaults: Vec::new(),
            overrides: Vec::new(),
        };
        for node in xml::child_elements(&doc, root) {
            let element = doc.element(node).expect("element");
            let content_type = element.get_attribute("ContentType").unwrap_or_default();
            match element.name.local_name.as_ref() {
                "Default" => types.defaults.push((
                    element
                        .get_attribute("Extension")
                        .unwrap_or_default()
                        .to_ascii_lowercase(),
                    content_type.to_string(),
                )),
                "Override" => types.overrides.push((
                    element
                        .get_attribute("PartName")
                        .unwrap_or_default()
                        .to_ascii_lowercase(),
                    content_type.to_string(),
                )),
                _ => {}
            }
        }
        Ok(types)
    }

    /// Content type of a part (part names are case insensitive).
    fn get(&self, part: &str) -> Option<&str> {
        let name = format!("/{}", part.to_ascii_lowercase());
        if let Some((_, content_type)) = self.overrides.iter().find(|(n, _)| *n == name) {
            return Some(content_type);
        }
        let extension = name.rsplit_once('.').map(|(_, e)| e)?;
        self.defaults
            .iter()
            .find(|(e, _)| e == extension)
            .map(|(_, content_type)| content_type.as_str())
    }
}

/// Reference URI of a part: `/name?ContentType=type`.
fn part_uri(name: &str, content_type: &str) -> String {
    format!("/{}?ContentType={content_type}", xades::uri_path(name))
}

/// Name of the part a reference URI points to.
fn part_of_uri(uri: &str) -> String {
    let path = uri.split('?').next().unwrap_or_default();
    percent_decode(path.trim_start_matches('/'))
}

/// Resolves reference URIs to the parts of `package`.
fn resolver<'a>(package: &'a RefCell<Package<'_>>) -> impl Fn(&str) -> Result<Vec<u8>> + 'a {
    move |uri: &str| {
        let name = part_of_uri(uri);
        let mut package = package.borrow_mut();
        // Part names are case insensitive.
        let name = package
            .names()
            .iter()
            .find(|n| n.eq_ignore_ascii_case(&name))
            .cloned()
            .unwrap_or(name);
        package.read(&name)
    }
}

/// References of the manifest: the relationship parts and the document parts.
fn manifest_references(package: &mut Package<'_>) -> Result<Vec<Reference>> {
    let content_types = ContentTypes::parse(&package.read(CONTENT_TYPES)?)?;
    let names = package.names().to_vec();
    let mut references: Vec<Reference> = Vec::new();
    for name in names.iter().filter(|n| n.ends_with(".rels")) {
        if name.starts_with("_xmlsignatures/") {
            continue;
        }
        let ids = relationships(&package.read(name)?)?
            .into_iter()
            .filter(|(_, kind, _)| !EXCLUDED_RELATIONSHIPS.contains(&kind.as_str()))
            .map(|(id, _, _)| id)
            .collect();
        references.push(Reference {
            id: None,
            type_uri: None,
            uri: part_uri(name, RELATIONSHIPS_CONTENT_TYPE),
            transforms: vec![
                Transform::Relationships {
                    ids,
                    types: Vec::new(),
                },
                Transform::C14n(C14nMode::Inclusive, Vec::new()),
            ],
        });
    }
    for name in &names {
        if !CONTENT_DIRS.iter().any(|dir| name.starts_with(dir)) {
            continue;
        }
        let Some(content_type) = content_types.get(name) else {
            continue;
        };
        let uri = part_uri(name, content_type);
        if !references.iter().any(|r| r.uri == uri) {
            references.push(Reference {
                id: None,
                type_uri: None,
                uri,
                transforms: Vec::new(),
            });
        }
    }
    Ok(references)
}

/// Office's `SignatureInfoV1`, with the values Office writes for a plain
/// signature (no signature line).
fn office_info(comments: Option<&str>) -> String {
    let mut out = format!(
        "<SignatureInfoV1 xmlns=\"{OFFICE_NS}\"><SetupID/><SignatureText/><SignatureImage/>"
    );
    match comments {
        Some(comments) => out.push_str(&format!(
            "<SignatureComments>{}</SignatureComments>",
            escape_text(comments)
        )),
        None => out.push_str("<SignatureComments/>"),
    }
    out.push_str(
        "<WindowsVersion>10.0</WindowsVersion><OfficeVersion>16.0</OfficeVersion>\
         <ApplicationVersion>16.0</ApplicationVersion><Monitors>1</Monitors>\
         <HorizontalResolution>1920</HorizontalResolution><VerticalResolution>1080</VerticalResolution>\
         <ColorDepth>32</ColorDepth><SignatureProviderId>{00000000-0000-0000-0000-000000000000}</SignatureProviderId>\
         <SignatureProviderUrl/><SignatureProviderDetails>9</SignatureProviderDetails>\
         <SignatureType>1</SignatureType></SignatureInfoV1>",
    );
    out
}

/// Inserts `insertion` before the end tag of the root element of `xml`; for
/// `<root/>`, the root gets an end tag.
fn insert_in_root(xml: &XmlText, insertion: &str) -> Result<String> {
    let doc = uppsala::parse(&xml.text).map_err(|e| Error::InvalidXml(e.to_string()))?;
    let root = doc
        .document_element()
        .ok_or_else(|| Error::InvalidXml("no tiene elemento raíz".to_string()))?;
    let range = doc
        .node_range(root)
        .ok_or_else(|| Error::InvalidXml("no se localiza el elemento raíz".to_string()))?;
    let text = &xml.text;
    if text[range.clone()].ends_with("/>") {
        let name = doc
            .element(root)
            .expect("element")
            .name
            .prefixed_name()
            .into_owned();
        let open = range.end - 2;
        return Ok(format!(
            "{}>{insertion}</{name}>{}",
            &text[..open],
            &text[range.end..]
        ));
    }
    let at = xml::end_tag_start(text, range)?;
    Ok(format!("{}{insertion}{}", &text[..at], &text[at..]))
}

/// Prefix (`p:` or empty) of the root element of `xml`, to add elements in its namespace.
fn root_prefix(xml: &XmlText) -> Result<String> {
    let doc = uppsala::parse(&xml.text).map_err(|e| Error::InvalidXml(e.to_string()))?;
    let root = doc
        .document_element()
        .ok_or_else(|| Error::InvalidXml("no tiene elemento raíz".to_string()))?;
    Ok(doc
        .element(root)
        .and_then(|e| e.name.prefix.as_deref())
        .map(|p| format!("{p}:"))
        .unwrap_or_default())
}

/// A signature of an OOXML document that waits for the private key operation.
#[derive(Debug, Clone)]
pub struct PreparedOoxml {
    document: Vec<u8>,
    signature_part: String,
    /// Other parts that change: content types, relationships, signature origin.
    changes: Vec<(String, Vec<u8>)>,
    signature: PreparedXades,
}

impl PreparedOoxml {
    /// Canonical `SignedInfo`: the bytes the private key must sign.
    pub fn to_be_signed(&self) -> &[u8] {
        self.signature.to_be_signed()
    }

    /// The signed document, from the raw signature value.
    pub fn finish(self, signature: &[u8]) -> Result<Vec<u8>> {
        let mut changes = self.changes;
        changes.push((self.signature_part, self.signature.finish(signature)?));
        Package::open(&self.document)?.rewrite(&changes)
    }
}

/// First phase of an OOXML signature (or co-signature, if the document is signed).
pub fn prepare(
    data: &[u8],
    chain: &[Certificate],
    key_type: KeyType,
    params: &OoxmlParams,
) -> Result<PreparedOoxml> {
    if DataKind::detect(data) != DataKind::Ooxml {
        return Err(Error::InvalidPackage(
            "no es un documento de Office (OOXML)".to_string(),
        ));
    }
    let leaf = chain
        .first()
        .ok_or_else(|| Error::Certificate("falta el certificado del firmante".to_string()))?;
    let mut package = Package::open(data)?;
    if !package.has(ROOT_RELATIONSHIPS) {
        return Err(Error::InvalidPackage(format!("falta {ROOT_RELATIONSHIPS}")));
    }
    let manifest = manifest_references(&mut package)?;
    if manifest.is_empty() {
        return Err(Error::InvalidPackage(
            "el documento no tiene partes que firmar".to_string(),
        ));
    }

    // Package changes: origin part, its relationships, root relationship, content types.
    let mut changes = Vec::new();
    let origin = match origin_part(&mut package)? {
        Some(origin) => origin,
        None => {
            let root_relationships = XmlText::decode(&package.read(ROOT_RELATIONSHIPS)?)?;
            let p = root_prefix(&root_relationships)?;
            let text = insert_in_root(
                &root_relationships,
                &format!(
                    r#"<{p}Relationship Id="rId-{}" Type="{ORIGIN_RELATIONSHIP}" Target="{DEFAULT_ORIGIN}"/>"#,
                    random::uuid()?
                ),
            )?;
            changes.push((
                ROOT_RELATIONSHIPS.to_string(),
                root_relationships.encode(&text),
            ));
            DEFAULT_ORIGIN.to_string()
        }
    };
    if !package.has(&origin) {
        changes.push((origin.clone(), Vec::new()));
    }
    let signature_dir = folder(&origin);
    let signature_part = (1..)
        .map(|n| {
            let name = format!("sig{n}.xml");
            if signature_dir.is_empty() {
                name
            } else {
                format!("{signature_dir}/{name}")
            }
        })
        .find(|name| !package.names().iter().any(|n| n.eq_ignore_ascii_case(name)))
        .expect("free part name");
    let signature_target = signature_part.rsplit('/').next().expect("name");
    let relationship = format!(
        r#"Relationship Id="rId-{}" Type="{SIGNATURE_RELATIONSHIP}" Target="{}"/>"#,
        random::uuid()?,
        escape_attr(signature_target)
    );
    let origin_relationships = relationships_part(&origin);
    if package.has(&origin_relationships) {
        let xml = XmlText::decode(&package.read(&origin_relationships)?)?;
        let p = root_prefix(&xml)?;
        let text = insert_in_root(&xml, &format!("<{p}{relationship}"))?;
        changes.push((origin_relationships, xml.encode(&text)));
    } else {
        changes.push((
            origin_relationships,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{RELATIONSHIPS_NS}"><{relationship}</Relationships>"#
            )
            .into_bytes(),
        ));
    }
    let content_types = XmlText::decode(&package.read(CONTENT_TYPES)?)?;
    let p = root_prefix(&content_types)?;
    let mut insertion = format!(
        r#"<{p}Override PartName="/{}" ContentType="{SIGNATURE_CONTENT_TYPE}"/>"#,
        escape_attr(&signature_part)
    );
    let origin_extension = origin.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    let types = ContentTypes::parse(&package.read(CONTENT_TYPES)?)?;
    if types.get(&origin).is_none() {
        match origin_extension {
            Some(extension) => insertion.push_str(&format!(
                r#"<{p}Default Extension="{}" ContentType="{ORIGIN_CONTENT_TYPE}"/>"#,
                escape_attr(&extension)
            )),
            None => insertion.push_str(&format!(
                r#"<{p}Override PartName="/{}" ContentType="{ORIGIN_CONTENT_TYPE}"/>"#,
                escape_attr(&origin)
            )),
        }
    }
    let text = insert_in_root(&content_types, &insertion)?;
    changes.push((CONTENT_TYPES.to_string(), content_types.encode(&text)));

    // The signature.
    let base = format!("xmldsig-{}", random::uuid()?);
    let references = vec![
        Reference {
            id: None,
            type_uri: Some(uri::OBJECT_TYPE.to_string()),
            uri: "#idPackageObject".to_string(),
            transforms: Vec::new(),
        },
        Reference {
            id: None,
            type_uri: Some(uri::OBJECT_TYPE.to_string()),
            uri: "#idOfficeObject".to_string(),
            transforms: Vec::new(),
        },
        Reference {
            id: None,
            type_uri: Some(uri::SIGNED_PROPERTIES_TYPE.to_string()),
            uri: format!("#{base}-SignedProperties"),
            transforms: vec![Transform::C14n(C14nMode::Inclusive, Vec::new())],
        },
        Reference {
            id: None,
            type_uri: None,
            uri: format!("#{base}-KeyInfo"),
            transforms: Vec::new(),
        },
    ];
    let mut text = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ds:Signature xmlns:ds="{DSIG_NS}" Id="{base}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{}"/><ds:SignatureMethod Algorithm="{}"/>"#,
        uri::C14N,
        signature_method_uri(key_type, params.digest)
    );
    let digest_slots = xades::write_references(&mut text, "ds:", &references, params.digest);
    text.push_str(&format!(
        r#"</ds:SignedInfo><ds:SignatureValue Id="{base}-SignatureValue">"#
    ));
    let value_slot = text.len();
    text.push_str("</ds:SignatureValue>");
    text.push_str(&xades::key_info(&base, chain, key_type)?);

    // Package object: the manifest and the signing time.
    text.push_str(r#"<ds:Object Id="idPackageObject"><ds:Manifest>"#);
    let manifest_slots = xades::write_references(&mut text, "ds:", &manifest, params.digest);
    let utc = DateTime::from_unix(params.signing_time, 0);
    text.push_str(&format!(
        "</ds:Manifest><ds:SignatureProperties><ds:SignatureProperty Id=\"idSignatureTime\" Target=\"#{base}\">\
         <mdssi:SignatureTime xmlns:mdssi=\"{MDSSI_NS}\"><mdssi:Format>YYYY-MM-DDThh:mm:ssTZD</mdssi:Format>\
         <mdssi:Value>{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z</mdssi:Value></mdssi:SignatureTime>\
         </ds:SignatureProperty></ds:SignatureProperties></ds:Object>",
        utc.year, utc.month, utc.day, utc.hour, utc.minute, utc.second
    ));
    // Office object.
    text.push_str(&format!(
        "<ds:Object Id=\"idOfficeObject\"><ds:SignatureProperties><ds:SignatureProperty Id=\"idOfficeV1Details\" Target=\"#{base}\">{}</ds:SignatureProperty></ds:SignatureProperties></ds:Object>",
        office_info(params.comments.as_deref())
    ));
    // XAdES.
    let xades_params = XadesParams {
        digest: params.digest,
        utc_offset_minutes: params.utc_offset_minutes,
        production_place: params.production_place.clone(),
        claimed_roles: params.claimed_roles.clone(),
        ..XadesParams::new(params.signing_time)
    };
    text.push_str(&format!(
        r##"<ds:Object><xades:QualifyingProperties xmlns:xades="{XADES_NS}" Target="#{base}">"##
    ));
    text.push_str(&xades::signed_properties(
        &base,
        leaf,
        &xades_params,
        &[],
        true,
    )?);
    text.push_str("</xades:QualifyingProperties></ds:Object></ds:Signature>");

    // The manifest digests go first: the package object digest depends on them.
    let package = RefCell::new(package);
    let resolve = resolver(&package);
    let filled = xades::complete(
        text,
        &base,
        &manifest,
        manifest_slots,
        0,
        params.digest,
        key_type,
        XmlText::utf8(),
        Some(&resolve),
    )?;
    // The manifest is after the SignatureValue: the offsets before it hold.
    let signature = xades::complete(
        filled.into_text(),
        &base,
        &references,
        digest_slots,
        value_slot,
        params.digest,
        key_type,
        XmlText::utf8(),
        Some(&resolve),
    )?;
    Ok(PreparedOoxml {
        document: data.to_vec(),
        signature_part,
        changes,
        signature,
    })
}

/// Signs an OOXML document; if it is signed, the new signature is added (co-signature).
pub fn sign(data: &[u8], key: &dyn SigningKey, params: &OoxmlParams) -> Result<Vec<u8>> {
    let prepared = prepare(data, key.certificate_chain(), key.key_type(), params)?;
    let signature = key.sign_raw(params.digest, prepared.to_be_signed())?;
    prepared.finish(&signature)
}

/// Verifies the signatures of an OOXML document, the parts referenced by
/// their manifests included. Certificate trust and revocation are not checked.
pub fn verify(data: &[u8]) -> Result<PackageReport> {
    let mut package = Package::open(data)?;
    let parts = signature_parts(&mut package)?;
    if parts.is_empty() {
        return Err(Error::InvalidSignature(
            "el documento no está firmado".to_string(),
        ));
    }
    let signatures = parts
        .iter()
        .map(|part| package.read(part))
        .collect::<Result<Vec<_>>>()?;
    let content_parts: Vec<String> = package
        .names()
        .iter()
        .filter(|name| CONTENT_DIRS.iter().any(|dir| name.starts_with(dir)))
        .cloned()
        .collect();
    let package = RefCell::new(package);
    let resolve = resolver(&package);
    let mut report = xades::XadesVerifyReport {
        signatures: Vec::new(),
    };
    for signature in signatures {
        report
            .signatures
            .extend(xades::verify_with(&signature, Some(&resolve), true)?.signatures);
    }
    let unsigned_parts = content_parts
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
                        .any(|uri| part_of_uri(uri).eq_ignore_ascii_case(part))
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

    pub(crate) fn docx() -> Vec<u8> {
        zip(&[
            ("[Content_Types].xml", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>"#),
            ("_rels/.rels", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#),
            ("word/document.xml", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hola</w:t></w:r></w:p></w:body></w:document>"#),
            ("word/_rels/document.xml.rels", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>"#),
            ("word/styles.xml", br#"<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>"#),
            ("docProps/core.xml", br#"<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"/>"#),
        ])
    }

    #[test]
    fn targets_and_part_names() {
        assert_eq!(
            resolve_target("", "_xmlsignatures/origin.sigs"),
            DEFAULT_ORIGIN
        );
        assert_eq!(
            resolve_target("_xmlsignatures", "sig1.xml"),
            "_xmlsignatures/sig1.xml"
        );
        assert_eq!(
            resolve_target("word", "../media/a%20b.png"),
            "media/a b.png"
        );
        assert_eq!(resolve_target("word", "/xl/x.xml"), "xl/x.xml");
        assert_eq!(
            relationships_part(DEFAULT_ORIGIN),
            "_xmlsignatures/_rels/origin.sigs.rels"
        );
        assert_eq!(
            part_of_uri("/word/a%20b.xml?ContentType=x/y"),
            "word/a b.xml"
        );
    }

    #[test]
    fn sign_cosign_and_verify() {
        let document = docx();
        assert_eq!(DataKind::detect(&document), DataKind::Ooxml);
        assert!(!is_signed(&document));
        let rsa = &load("rsa.p12")[0];
        let ec = &load("ec.p12")[0];
        let signed = sign(
            &document,
            rsa,
            &OoxmlParams {
                comments: Some("Aprobado".to_string()),
                ..OoxmlParams::new(1_792_428_983)
            },
        )
        .unwrap();
        assert!(is_signed(&signed));
        let report = verify(&signed).unwrap();
        assert!(report.is_valid(), "{report:?}");
        // The manifest covers the document parts and their relationships.
        let uris = &report.signatures.signatures[0].uris;
        for part in [
            "/_rels/.rels?",
            "/word/_rels/document.xml.rels?",
            "/word/document.xml?",
            "/word/styles.xml?",
        ] {
            assert!(
                uris.iter().any(|u| u.starts_with(part)),
                "{part} in {uris:?}"
            );
        }

        let cosigned = sign(
            &signed,
            ec,
            &OoxmlParams {
                digest: DigestAlgorithm::Sha256,
                ..OoxmlParams::new(1_792_428_983)
            },
        )
        .unwrap();
        let mut package = Package::open(&cosigned).unwrap();
        assert!(package.has("_xmlsignatures/sig2.xml"));
        let origin = package
            .read("_xmlsignatures/_rels/origin.sigs.rels")
            .unwrap();
        assert_eq!(relationships(&origin).unwrap().len(), 2);
        let report = verify(&cosigned).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.signatures.signatures.len(), 2);

        // A signed part changed.
        let tampered = Package::open(&cosigned)
            .unwrap()
            .rewrite(&[("word/document.xml".to_string(), b"<x/>".to_vec())])
            .unwrap();
        assert!(!verify(&tampered).unwrap().is_valid());
        // A relationship added to a signed relationships part.
        let rels = br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId9" Type="urn:x" Target="x.xml"/></Relationships>"#;
        let added = Package::open(&cosigned)
            .unwrap()
            .rewrite(&[("word/_rels/document.xml.rels".to_string(), rels.to_vec())])
            .unwrap();
        assert!(verify(&added).unwrap().is_valid());
        // An unsigned part in the document folder.
        let added = Package::open(&cosigned)
            .unwrap()
            .rewrite(&[("word/macro.bin".to_string(), b"x".to_vec())])
            .unwrap();
        let report = verify(&added).unwrap();
        assert_eq!(report.unsigned_parts, ["word/macro.bin"]);
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/data/ooxml/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn verifies_and_cosigns_autofirma_documents() {
        let key = &load("ec.p12")[0];
        for name in ["autofirma-rsa.docx", "autofirma-ec.docx"] {
            let signed = fixture(name);
            assert!(is_signed(&signed), "{name}");
            let report = verify(&signed).unwrap();
            assert!(report.is_valid(), "{name}: {report:?}");
            let cosigned = sign(&signed, key, &OoxmlParams::new(1_792_428_983)).unwrap();
            let report = verify(&cosigned).unwrap();
            assert!(report.is_valid(), "{name}: {report:?}");
            assert_eq!(report.signatures.signatures.len(), 2);
        }
        // A LibreOffice document, whose [Content_Types].xml is the last part.
        let document = fixture("doc.docx");
        assert_eq!(DataKind::detect(&document), DataKind::Ooxml);
        let signed = sign(&document, key, &OoxmlParams::new(1_792_428_983)).unwrap();
        assert!(verify(&signed).unwrap().is_valid());
    }
}
