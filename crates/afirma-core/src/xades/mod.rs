//! XAdES-BES / XAdES-EPES signatures (ETSI TS 101 903 v1.3.2), with the same
//! structure AutoFirma produces:
//!
//! * three references: the data, the `SignedProperties` and the `KeyInfo`;
//! * `SigningTime`, `SigningCertificate` (v1) and, optionally,
//!   `SignaturePolicyIdentifier`, `SignatureProductionPlace` and `SignerRole`;
//!   a `DataObjectFormat` with the MIME type of the data;
//! * the certificate chain and, for RSA, the public key in `KeyInfo`;
//! * enveloping (AutoFirma's default: the data inside a `ds:Object`), enveloped
//!   (the signature inside the XML document) or detached (data and signature
//!   side by side under an `AFIRMA` root element). Binary data travels in Base64.
//!
//! Enveloped signatures keep the original document bytes and encoding; the
//! signature is inserted as the last child of the root element.
//!
//! Like CAdES, signing has two phases ([`prepare`] and
//! [`PreparedXades::finish`]) so the private key operation can happen elsewhere.

use bergshamra_c14n::C14nMode;
use bergshamra_xml::uppsala;
use der::{Decode, Encode, Sequence, asn1::UintRef};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::{
    algorithm::KeyType,
    cert::{decimal, rfc2253},
    digest::DigestAlgorithm,
    error::{Error, Result},
    format::{DataKind, mime_type, mime_type_oid},
    keystore::SigningKey,
    policy::SignaturePolicy,
    random,
    time::DateTime,
    xml::{
        self, DSIG_NS, XADES_NS, XmlText, base64, digest_uri, escape_attr, escape_text,
        signature_method_uri, uri,
    },
};

pub(crate) mod reference;
mod verify;

use reference::{Ids, Transform};
pub use verify::{XadesSignatureReport, XadesVerifyReport, verify};

/// Where the signed data goes (AutoFirma's `format`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum XadesFormat {
    /// The data inside the signature (`XAdES Enveloping`, AutoFirma's default).
    #[default]
    Enveloping,
    /// The signature inside the XML document (`XAdES Enveloped`).
    Enveloped,
    /// Data and signature side by side in a new document (`XAdES Detached`).
    Detached,
}

impl XadesFormat {
    /// Name as used in AutoFirma's `format` parameter.
    pub fn name(self) -> &'static str {
        match self {
            XadesFormat::Enveloping => "XAdES Enveloping",
            XadesFormat::Enveloped => "XAdES Enveloped",
            XadesFormat::Detached => "XAdES Detached",
        }
    }
}

/// Where the signature was made (`SignatureProductionPlace`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionPlace {
    /// City (`signatureProductionCity`).
    pub city: Option<String>,
    /// Province (`signatureProductionProvince`).
    pub province: Option<String>,
    /// Postal code (`signatureProductionPostalCode`).
    pub postal_code: Option<String>,
    /// Country (`signatureProductionCountry`).
    pub country: Option<String>,
}

impl ProductionPlace {
    fn is_empty(&self) -> bool {
        [&self.city, &self.province, &self.postal_code, &self.country]
            .iter()
            .all(|value| value.is_none())
    }
}

/// Parameters of a XAdES signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XadesParams {
    /// Digest algorithm of the signature and of the references (AutoFirma's default is SHA-512).
    pub digest: DigestAlgorithm,
    /// Enveloping, enveloped or detached.
    pub format: XadesFormat,
    /// Signature policy, turning the signature into XAdES-EPES.
    pub policy: Option<SignaturePolicy>,
    /// Signing time, seconds since the Unix epoch.
    pub signing_time: i64,
    /// Local time offset from UTC in minutes, for `SigningTime`.
    pub utc_offset_minutes: i32,
    /// Where the signature was made.
    pub production_place: ProductionPlace,
    /// Roles claimed by the signer (`signerClaimedRoles`).
    pub claimed_roles: Vec<String>,
}

impl XadesParams {
    /// AutoFirma's defaults: XAdES-BES enveloping with SHA-512.
    pub fn new(signing_time: i64) -> Self {
        XadesParams {
            digest: DigestAlgorithm::Sha512,
            format: XadesFormat::Enveloping,
            policy: None,
            signing_time,
            utc_offset_minutes: 0,
            production_place: ProductionPlace::default(),
            claimed_roles: Vec::new(),
        }
    }
}

/// Variations of the layout for other formats built on XAdES.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Profile<'a> {
    /// Canonicalization transform on the data reference.
    pub canonicalize_data: bool,
    /// AutoFirma's XPath filter on enveloped signatures.
    pub xpath_filter: bool,
    /// ASiC-S: the data is this file of the container, referenced by its name
    /// from an `asic:XAdESSignatures` document. `XadesParams::format` is ignored.
    pub asic_file: Option<&'a str>,
}

impl Profile<'_> {
    /// AutoFirma's XAdES.
    pub const XADES: Profile<'static> = Profile {
        canonicalize_data: true,
        xpath_filter: true,
        asic_file: None,
    };
}

/// ASiC namespace (ETSI TS 102 918).
pub(crate) const ASIC_NS: &str = "http://uri.etsi.org/02918/v1.2.1#";

/// A signature whose `SignedInfo` is ready to be signed.
#[derive(Debug, Clone)]
pub struct PreparedXades {
    /// Encoding of the output document.
    output: XmlText,
    /// The signed document without the signature value.
    text: String,
    /// Offset of the `SignatureValue` content in `text`.
    signature_value_at: usize,
    to_be_signed: Vec<u8>,
    key_type: KeyType,
}

impl PreparedXades {
    /// Canonical `SignedInfo`: the bytes the private key must sign (hashing them
    /// with the signature's digest algorithm).
    pub fn to_be_signed(&self) -> &[u8] {
        &self.to_be_signed
    }

    /// Builds the signed XML document from the raw signature value (PKCS#1, or
    /// DER encoded ECDSA as [`SigningKey::sign_raw`] returns it).
    pub fn finish(mut self, signature: &[u8]) -> Result<Vec<u8>> {
        let value = xml::signature_value(self.key_type, signature)?;
        self.text
            .insert_str(self.signature_value_at, &base64(&value));
        Ok(self.output.encode(&self.text))
    }
}

/// Signs `data` with `key`, producing a XAdES-BES (or EPES, with a policy) signature.
pub fn sign(data: &[u8], key: &dyn SigningKey, params: &XadesParams) -> Result<Vec<u8>> {
    let prepared = prepare(data, key.certificate_chain(), key.key_type(), params)?;
    let signature = key.sign_raw(params.digest, prepared.to_be_signed())?;
    prepared.finish(&signature)
}

/// First phase of a XAdES signature: builds the document with the signature
/// and its references.
///
/// `chain` is the signer's certificate chain, leaf first.
pub fn prepare(
    data: &[u8],
    chain: &[Certificate],
    key_type: KeyType,
    params: &XadesParams,
) -> Result<PreparedXades> {
    prepare_with(data, chain, key_type, params, Profile::XADES)
}

/// An XML document being signed.
struct XmlData {
    source: XmlText,
    /// Byte range of the root element in `source.text`.
    root: std::ops::Range<usize>,
    /// Qualified name of the root element.
    root_name: String,
    /// `Id` attribute of the root element.
    root_id: Option<String>,
    /// The root element as it is embedded in enveloping and detached signatures.
    embedded: String,
}

impl XmlData {
    fn parse(data: &[u8]) -> Result<Self> {
        let source = XmlText::decode(data)?;
        let doc = uppsala::parse(&source.text).map_err(|e| Error::InvalidXml(e.to_string()))?;
        let root = doc
            .document_element()
            .ok_or_else(|| Error::InvalidXml("no tiene elemento raíz".to_string()))?;
        let range = doc
            .node_range(root)
            .ok_or_else(|| Error::InvalidXml("no se localiza el elemento raíz".to_string()))?;
        let element = doc.element(root).expect("document element");
        // Entities declared in a DOCTYPE would be undefined inside the signature:
        // embed the canonical (entity free) form instead.
        let embedded = if source.text[..range.start].contains("<!DOCTYPE") {
            String::from_utf8(reference::canonicalize_element(
                &doc,
                root,
                C14nMode::Inclusive,
                &[],
            )?)
            .map_err(|e| Error::InvalidXml(e.to_string()))?
        } else {
            source.text[range.clone()].to_string()
        };
        Ok(XmlData {
            root_name: element.name.prefixed_name().into_owned(),
            root_id: element.get_attribute("Id").map(str::to_string),
            embedded,
            root: range,
            source,
        })
    }
}

/// Where the signature goes.
#[derive(Clone, Copy)]
enum Placement<'a> {
    Format(XadesFormat),
    Asic(&'a str),
}

/// A file name as a relative URI reference: bytes other than unreserved
/// characters and `/` are percent-encoded.
fn uri_path(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(char::from(b))
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A reference of `SignedInfo`.
struct Reference {
    id: Option<String>,
    type_uri: Option<&'static str>,
    uri: String,
    transforms: Vec<Transform>,
}

pub(crate) fn prepare_with(
    data: &[u8],
    chain: &[Certificate],
    key_type: KeyType,
    params: &XadesParams,
    profile: Profile<'_>,
) -> Result<PreparedXades> {
    if data.is_empty() {
        return Err(Error::EmptyData);
    }
    let leaf = chain
        .first()
        .ok_or_else(|| Error::Certificate("falta el certificado del firmante".to_string()))?;

    // Binary data (anything that is not well formed XML) travels in Base64.
    let xml_data = match DataKind::detect(data) {
        DataKind::Xml if profile.asic_file.is_none() => match XmlData::parse(data) {
            Ok(xml_data) => Some(xml_data),
            Err(e) if params.format == XadesFormat::Enveloped => return Err(e),
            Err(_) => None,
        },
        _ => None,
    };
    let mime = if xml_data.is_some() {
        "text/xml".to_string()
    } else {
        mime_type(data)
    };

    let base = format!("Signature-{}", random::uuid()?);
    let data_reference_id = format!("Reference-{}", random::uuid()?);
    let declaration = r#"<?xml version="1.0" encoding="UTF-8"?>"#;
    let (content, content_transform, encoding) = match &xml_data {
        Some(xml_data) => (
            xml_data.embedded.clone(),
            profile
                .canonicalize_data
                .then(|| Transform::C14n(C14nMode::Inclusive, Vec::new())),
            None,
        ),
        None if profile.asic_file.is_some() => (String::new(), None, None),
        None => (base64(data), Some(Transform::Base64), Some(uri::BASE64)),
    };
    let content_attributes = |id: &str| {
        let mut attributes = String::new();
        if let Some(encoding) = encoding {
            attributes.push_str(&format!(r#" Encoding="{encoding}""#));
        }
        attributes.push_str(&format!(r#" Id="{id}" MimeType="{}""#, escape_attr(&mime)));
        attributes
    };

    // The document around the signature and the data reference.
    let mut enveloping_object = None;
    let placement = match profile.asic_file {
        Some(file_name) => Placement::Asic(file_name),
        None => Placement::Format(params.format),
    };
    let (prefix, suffix, data_reference, output) = match placement {
        Placement::Asic(file_name) => {
            let reference = Reference {
                id: Some(data_reference_id.clone()),
                type_uri: None,
                uri: uri_path(file_name),
                transforms: Vec::new(),
            };
            (
                format!(r#"{declaration}<asic:XAdESSignatures xmlns:asic="{ASIC_NS}">"#),
                "</asic:XAdESSignatures>".to_string(),
                reference,
                XmlText::utf8(),
            )
        }
        Placement::Format(XadesFormat::Enveloped) => {
            let Some(xml_data) = xml_data else {
                return Err(Error::Unsupported(
                    "las firmas XAdES Enveloped solo pueden hacerse sobre datos XML".to_string(),
                ));
            };
            let text = &xml_data.source.text;
            let root_text = &text[xml_data.root.clone()];
            let (prefix, suffix) = if root_text.ends_with("/>") {
                // `<root .../>` becomes `<root ...>SIGNATURE</root>`.
                let open = xml_data.root.end - 2;
                (
                    format!("{}>", &text[..open]),
                    format!("</{}>{}", xml_data.root_name, &text[xml_data.root.end..]),
                )
            } else {
                let end_tag = xml_data.root.start
                    + root_text
                        .rfind("</")
                        .ok_or_else(|| Error::InvalidXml("falta la etiqueta de cierre".into()))?;
                (text[..end_tag].to_string(), text[end_tag..].to_string())
            };
            let mut transforms = vec![Transform::Enveloped];
            if profile.canonicalize_data {
                transforms.push(Transform::C14n(C14nMode::Inclusive, Vec::new()));
            }
            if profile.xpath_filter {
                transforms.push(Transform::NotSignatures);
            }
            let reference = Reference {
                id: Some(data_reference_id.clone()),
                type_uri: None,
                uri: xml_data
                    .root_id
                    .as_ref()
                    .map(|id| format!("#{id}"))
                    .unwrap_or_default(),
                transforms,
            };
            (prefix, suffix, reference, xml_data.source)
        }
        Placement::Format(XadesFormat::Enveloping) => {
            let object_id = format!("Object-{}", random::uuid()?);
            enveloping_object = Some(format!(
                "<ds:Object{}>{content}</ds:Object>",
                content_attributes(&object_id)
            ));
            let reference = Reference {
                id: Some(data_reference_id.clone()),
                type_uri: Some(uri::OBJECT_TYPE),
                uri: format!("#{object_id}"),
                transforms: content_transform.into_iter().collect(),
            };
            (
                declaration.to_string(),
                String::new(),
                reference,
                XmlText::utf8(),
            )
        }
        Placement::Format(XadesFormat::Detached) => {
            let content_id = format!("CONTENT-{}", random::uuid()?);
            let prefix = format!(
                r#"{declaration}<AFIRMA Id="AFIRMA-Root-{}"><CONTENT{}>{content}</CONTENT>"#,
                random::uuid()?,
                content_attributes(&content_id)
            );
            let reference = Reference {
                id: Some(data_reference_id.clone()),
                type_uri: None,
                uri: format!("#{content_id}"),
                transforms: content_transform.into_iter().collect(),
            };
            (prefix, "</AFIRMA>".to_string(), reference, XmlText::utf8())
        }
    };

    let references = [
        data_reference,
        Reference {
            id: None,
            type_uri: Some(uri::SIGNED_PROPERTIES_TYPE),
            uri: format!("#{base}-SignedProperties"),
            transforms: Vec::new(),
        },
        Reference {
            id: None,
            type_uri: None,
            uri: format!("#{base}-KeyInfo"),
            transforms: Vec::new(),
        },
    ];

    // The signature, with empty `DigestValue`s and `SignatureValue`.
    let digest_method = format!(
        r#"<ds:DigestMethod Algorithm="{}"/>"#,
        digest_uri(params.digest)
    );
    let mut signature = format!(
        r#"<ds:Signature xmlns:ds="{DSIG_NS}" Id="{base}-Signature"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{}"/><ds:SignatureMethod Algorithm="{}"/>"#,
        uri::C14N,
        signature_method_uri(key_type, params.digest)
    );
    let mut digest_slots = Vec::new();
    for reference in &references {
        signature.push_str("<ds:Reference");
        if let Some(id) = &reference.id {
            signature.push_str(&format!(r#" Id="{id}""#));
        }
        if let Some(type_uri) = reference.type_uri {
            signature.push_str(&format!(r#" Type="{type_uri}""#));
        }
        signature.push_str(&format!(r#" URI="{}">"#, escape_attr(&reference.uri)));
        if !reference.transforms.is_empty() {
            signature.push_str("<ds:Transforms>");
            for transform in &reference.transforms {
                signature.push_str(&transform.to_xml());
            }
            signature.push_str("</ds:Transforms>");
        }
        signature.push_str(&digest_method);
        signature.push_str("<ds:DigestValue>");
        digest_slots.push(signature.len());
        signature.push_str("</ds:DigestValue></ds:Reference>");
    }
    signature.push_str(&format!(
        r#"</ds:SignedInfo><ds:SignatureValue Id="{base}-SignatureValue">"#
    ));
    let signature_value_slot = signature.len();
    signature.push_str("</ds:SignatureValue>");
    signature.push_str(&key_info(&base, chain, key_type)?);
    if let Some(object) = enveloping_object {
        signature.push_str(&object);
    }
    signature.push_str(&format!(
        r##"<ds:Object><xades:QualifyingProperties xmlns:xades="{XADES_NS}" Id="{base}-QualifyingProperties" Target="#{base}-Signature">"##
    ));
    signature.push_str(&signed_properties(
        &base,
        leaf,
        params,
        &data_reference_id,
        &mime,
        encoding,
    )?);
    signature.push_str("</xades:QualifyingProperties></ds:Object></ds:Signature>");

    let offset = prefix.len();
    let mut text = format!("{prefix}{signature}{suffix}");

    // Digests of the references, in the final document.
    let digests = {
        let doc = uppsala::parse(&text).map_err(|e| Error::InvalidXml(e.to_string()))?;
        let ids = Ids::new(&doc);
        let signature_node = ids.get(&format!("{base}-Signature"))?;
        references
            .iter()
            .map(|reference| {
                reference::digest(
                    &doc,
                    &ids,
                    signature_node,
                    &reference.uri,
                    &reference.transforms,
                    params.digest,
                    profile.asic_file.map(|_| data),
                )
                .map(|digest| base64(&digest))
            })
            .collect::<Result<Vec<_>>>()?
    };
    for (slot, digest) in digest_slots.iter().zip(&digests).rev() {
        text.insert_str(offset + slot, digest);
    }
    let signature_value_at =
        offset + signature_value_slot + digests.iter().map(String::len).sum::<usize>();

    let to_be_signed = {
        let doc = uppsala::parse(&text).map_err(|e| Error::InvalidXml(e.to_string()))?;
        let ids = Ids::new(&doc);
        let signed_info = xml::child(
            &doc,
            ids.get(&format!("{base}-Signature"))?,
            DSIG_NS,
            "SignedInfo",
        )
        .ok_or_else(|| Error::InvalidXml("falta SignedInfo".to_string()))?;
        reference::canonicalize_element(&doc, signed_info, C14nMode::Inclusive, &[])?
    };

    Ok(PreparedXades {
        output,
        text,
        signature_value_at,
        to_be_signed,
        key_type,
    })
}

/// `ds:KeyInfo`: the certificate chain and, for RSA, the public key.
fn key_info(base: &str, chain: &[Certificate], key_type: KeyType) -> Result<String> {
    let mut out = format!(r#"<ds:KeyInfo Id="{base}-KeyInfo"><ds:X509Data>"#);
    for cert in chain {
        out.push_str(&format!(
            "<ds:X509Certificate>{}</ds:X509Certificate>",
            base64(&cert.to_der()?)
        ));
    }
    out.push_str("</ds:X509Data>");
    if key_type == KeyType::Rsa {
        let spki = chain[0].tbs_certificate().subject_public_key_info();
        let key = RsaPublicKey::from_der(spki.subject_public_key.raw_bytes())?;
        out.push_str(&format!(
            "<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>{}</ds:Modulus><ds:Exponent>{}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>",
            base64(key.modulus.as_bytes()),
            base64(key.public_exponent.as_bytes())
        ));
    }
    out.push_str("</ds:KeyInfo>");
    Ok(out)
}

/// PKCS#1 `RSAPublicKey`.
#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

/// `xades:SignedProperties`.
fn signed_properties(
    base: &str,
    leaf: &Certificate,
    params: &XadesParams,
    data_reference_id: &str,
    mime: &str,
    encoding: Option<&str>,
) -> Result<String> {
    let digest_method =
        |digest| format!(r#"<ds:DigestMethod Algorithm="{}"/>"#, digest_uri(digest));
    let tbs = leaf.tbs_certificate();
    let mut out = format!(
        "<xades:SignedProperties Id=\"{base}-SignedProperties\"><xades:SignedSignatureProperties>\
         <xades:SigningTime>{}</xades:SigningTime>\
         <xades:SigningCertificate><xades:Cert><xades:CertDigest>{}<ds:DigestValue>{}</ds:DigestValue></xades:CertDigest>\
         <xades:IssuerSerial><ds:X509IssuerName>{}</ds:X509IssuerName><ds:X509SerialNumber>{}</ds:X509SerialNumber></xades:IssuerSerial>\
         </xades:Cert></xades:SigningCertificate>",
        DateTime::from_unix(params.signing_time, params.utc_offset_minutes).to_xml(),
        digest_method(params.digest),
        base64(&params.digest.digest(&leaf.to_der()?)),
        escape_text(&rfc2253(tbs.issuer())),
        decimal(tbs.serial_number().as_bytes()),
    );

    if let Some(policy) = &params.policy {
        out.push_str(&signature_policy(
            policy,
            digest_method(policy.hash_algorithm),
        ));
    }

    let place = &params.production_place;
    if !place.is_empty() {
        out.push_str("<xades:SignatureProductionPlace>");
        for (element, value) in [
            ("City", &place.city),
            ("StateOrProvince", &place.province),
            ("PostalCode", &place.postal_code),
            ("CountryName", &place.country),
        ] {
            if let Some(value) = value {
                out.push_str(&format!(
                    "<xades:{element}>{}</xades:{element}>",
                    escape_text(value)
                ));
            }
        }
        out.push_str("</xades:SignatureProductionPlace>");
    }

    let roles: Vec<&String> = params
        .claimed_roles
        .iter()
        .filter(|role| !role.trim().is_empty())
        .collect();
    if !roles.is_empty() {
        out.push_str("<xades:SignerRole><xades:ClaimedRoles>");
        for role in roles {
            out.push_str(&format!(
                "<xades:ClaimedRole>{}</xades:ClaimedRole>",
                escape_text(role)
            ));
        }
        out.push_str("</xades:ClaimedRoles></xades:SignerRole>");
    }
    out.push_str("</xades:SignedSignatureProperties>");

    // DataObjectFormat, with the OID of the MIME type when AutoFirma knows one.
    out.push_str(&format!(
        r##"<xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference="#{data_reference_id}"><xades:Description/>"##
    ));
    if let Some(oid) = mime_type_oid(mime) {
        out.push_str(&format!(
            r#"<xades:ObjectIdentifier><xades:Identifier Qualifier="OIDAsURN">urn:oid:{oid}</xades:Identifier><xades:Description/></xades:ObjectIdentifier>"#
        ));
    }
    out.push_str(&format!(
        "<xades:MimeType>{}</xades:MimeType>",
        escape_text(mime)
    ));
    match encoding {
        Some(encoding) => out.push_str(&format!("<xades:Encoding>{encoding}</xades:Encoding>")),
        None => out.push_str("<xades:Encoding/>"),
    }
    out.push_str(
        "</xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties>",
    );
    Ok(out)
}

/// `xades:SignaturePolicyIdentifier`. OIDs are written as URNs (`urn:oid:...`), as AutoFirma does.
fn signature_policy(policy: &SignaturePolicy, digest_method: String) -> String {
    let identifier = policy.identifier.trim();
    let identifier = if !identifier.to_ascii_lowercase().starts_with("urn:oid:")
        && const_oid::ObjectIdentifier::new(identifier).is_ok()
    {
        format!("urn:oid:{identifier}")
    } else {
        identifier.to_string()
    };
    let mut out = format!(
        "<xades:SignaturePolicyIdentifier><xades:SignaturePolicyId><xades:SigPolicyId>\
         <xades:Identifier>{}</xades:Identifier><xades:Description/></xades:SigPolicyId>\
         <xades:SigPolicyHash>{digest_method}<ds:DigestValue>{}</ds:DigestValue></xades:SigPolicyHash>",
        escape_text(&identifier),
        escape_text(policy.hash_base64.trim()),
    );
    if let Some(qualifier) = &policy.qualifier {
        out.push_str(&format!(
            "<xades:SigPolicyQualifiers><xades:SigPolicyQualifier><xades:SPURI>{}</xades:SPURI>\
             </xades:SigPolicyQualifier></xades:SigPolicyQualifiers>",
            escape_text(qualifier)
        ));
    }
    out.push_str("</xades:SignaturePolicyId></xades:SignaturePolicyIdentifier>");
    out
}

/// `ds:Signature` elements with XAdES properties and no signature timestamp,
/// with their `QualifyingProperties`.
fn untimestamped(doc: &uppsala::Document<'_>) -> Vec<(uppsala::NodeId, uppsala::NodeId)> {
    doc.descendants(doc.root())
        .into_iter()
        .filter(|&node| xml::is_element(doc, node, DSIG_NS, "Signature"))
        .filter_map(|signature| {
            let qualifying = xml::children(doc, signature, DSIG_NS, "Object")
                .into_iter()
                .find_map(|object| {
                    xml::child_elements(doc, object).into_iter().find(|&child| {
                        doc.element(child)
                            .is_some_and(|e| e.name.local_name == "QualifyingProperties")
                    })
                })?;
            let timestamped = doc.descendants(qualifying).into_iter().any(|node| {
                doc.element(node)
                    .is_some_and(|e| e.name.local_name == "SignatureTimeStamp")
            });
            (!timestamped).then_some((signature, qualifying))
        })
        .collect()
}

/// Digest of the canonical `SignatureValue` of `signature`, the input of XAdES-T.
fn signature_value_imprint(
    doc: &uppsala::Document<'_>,
    signature: uppsala::NodeId,
    digest: DigestAlgorithm,
) -> Result<Vec<u8>> {
    let value = xml::child(doc, signature, DSIG_NS, "SignatureValue")
        .ok_or_else(|| Error::InvalidSignature("falta SignatureValue".to_string()))?;
    Ok(digest.digest(&reference::canonicalize_element(
        doc,
        value,
        C14nMode::Inclusive,
        &[],
    )?))
}

/// Digests to timestamp for XAdES-T: the canonical `SignatureValue` of every
/// XAdES signature of `xml` without a signature timestamp, computed with `digest`.
pub fn timestamp_imprints(xml: &[u8], digest: DigestAlgorithm) -> Result<Vec<Vec<u8>>> {
    let source = XmlText::decode(xml)?;
    let doc = uppsala::parse(&source.text).map_err(|e| Error::InvalidXml(e.to_string()))?;
    untimestamped(&doc)
        .into_iter()
        .map(|(signature, _)| signature_value_imprint(&doc, signature, digest))
        .collect()
}

/// Adds signature timestamps (XAdES-T) from TSA `responses` to the
/// signatures they timestamp, as `xades:UnsignedProperties`.
pub fn add_timestamps(
    xml: &[u8],
    digest: DigestAlgorithm,
    responses: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let source = XmlText::decode(xml)?;
    let doc = uppsala::parse(&source.text).map_err(|e| Error::InvalidXml(e.to_string()))?;
    let mut pending: Vec<&Vec<u8>> = responses.iter().collect();
    // (offset, text) insertions.
    let mut insertions = Vec::new();
    for (signature, qualifying) in untimestamped(&doc) {
        let imprint = signature_value_imprint(&doc, signature, digest)?;
        let Some(position) = pending
            .iter()
            .position(|response| crate::tsp::token_for(response, digest, &imprint).is_ok())
        else {
            continue;
        };
        let token = crate::tsp::token_for(pending.remove(position), digest, &imprint)?;
        let element = doc.element(qualifying).expect("element");
        let ns = element.name.namespace_uri.as_deref().unwrap_or(XADES_NS);
        let timestamp = format!(
            r#"<xades:SignatureTimeStamp><ds:CanonicalizationMethod Algorithm="{}"/><xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>"#,
            uri::C14N,
            base64(&token)
        );
        let declarations = format!(r#" xmlns:xades="{ns}" xmlns:ds="{DSIG_NS}""#);
        let unsigned_signature_properties = xml::child(&doc, qualifying, ns, "UnsignedProperties")
            .and_then(|unsigned| xml::child(&doc, unsigned, ns, "UnsignedSignatureProperties"));
        let (container, text) = match unsigned_signature_properties {
            Some(properties) => (
                properties,
                timestamp.replacen(
                    "<xades:SignatureTimeStamp",
                    &format!("<xades:SignatureTimeStamp{declarations}"),
                    1,
                ),
            ),
            None => (
                qualifying,
                format!(
                    "<xades:UnsignedProperties{declarations}><xades:UnsignedSignatureProperties>{timestamp}</xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
                ),
            ),
        };
        let range = doc
            .node_range(container)
            .ok_or_else(|| Error::InvalidXml("no se localiza la firma".to_string()))?;
        let element_text = &source.text[range.clone()];
        if element_text.ends_with("/>") {
            return Err(Error::Unsupported("propiedades XAdES vacías".to_string()));
        }
        let end_tag = range.start + element_text.rfind("</").expect("closing tag");
        insertions.push((end_tag, text));
    }
    if let Some(response) = pending.first() {
        crate::tsp::parse_response(response)?;
        return Err(Error::Timestamp(
            "el sello de tiempo no corresponde a la firma".to_string(),
        ));
    }
    let mut text = source.text.clone();
    insertions.sort_by_key(|(offset, _)| std::cmp::Reverse(*offset));
    for (offset, insertion) in insertions {
        text.insert_str(offset, &insertion);
    }
    Ok(source.encode(&text))
}

#[cfg(test)]
mod tests;
