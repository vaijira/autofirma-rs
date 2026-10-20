//! Helpers shared by the XMLDSig based formats: namespaces and algorithm URIs,
//! escaping, Base64, signature value encodings and documents in encodings other
//! than UTF-8.

use base64ct::{Base64, Encoding as _};
use bergshamra_xml::uppsala::{Document, NodeId, NodeKind};
use encoding_rs::Encoding;

use crate::{
    algorithm::KeyType,
    digest::DigestAlgorithm,
    error::{Error, Result},
};

/// XMLDSig namespace.
pub(crate) const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// XAdES 1.3.2 namespace, the one AutoFirma uses.
pub(crate) const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
/// Older XAdES namespaces still found in signatures.
pub(crate) const XADES_OLD_NS: [&str; 2] = [
    "http://uri.etsi.org/01903/v1.2.2#",
    "http://uri.etsi.org/01903/v1.1.1#",
];

/// Algorithm and type URIs.
pub(crate) mod uri {
    /// Canonical XML 1.0.
    pub const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    /// Enveloped signature transform.
    pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    /// Base64 transform, also the `Encoding` of Base64 content.
    pub const BASE64: &str = "http://www.w3.org/2000/09/xmldsig#base64";
    /// XPath filter transform.
    pub const XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
    /// Reference to a `ds:Object`.
    pub const OBJECT_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#Object";
    /// Reference to the XAdES `SignedProperties`.
    pub const SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
}

/// URI of a digest algorithm.
pub(crate) fn digest_uri(digest: DigestAlgorithm) -> &'static str {
    match digest {
        DigestAlgorithm::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
        DigestAlgorithm::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        DigestAlgorithm::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        DigestAlgorithm::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
    }
}

/// Digest algorithm of a URI.
pub(crate) fn digest_from_uri(uri: &str) -> Option<DigestAlgorithm> {
    [
        DigestAlgorithm::Sha1,
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ]
    .into_iter()
    .find(|&digest| digest_uri(digest) == uri)
}

/// URI of a signature algorithm (`rsa-sha512`, `ecdsa-sha256`...).
pub(crate) fn signature_method_uri(key_type: KeyType, digest: DigestAlgorithm) -> &'static str {
    match (key_type, digest) {
        (KeyType::Rsa, DigestAlgorithm::Sha1) => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        (KeyType::Rsa, DigestAlgorithm::Sha256) => {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        }
        (KeyType::Rsa, DigestAlgorithm::Sha384) => {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
        }
        (KeyType::Rsa, DigestAlgorithm::Sha512) => {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
        }
        (_, DigestAlgorithm::Sha1) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
        (_, DigestAlgorithm::Sha256) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        (_, DigestAlgorithm::Sha384) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        (_, DigestAlgorithm::Sha512) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
    }
}

/// Whether a signature method is RSA (`false` for ECDSA) and its digest.
pub(crate) fn signature_method_from_uri(uri: &str) -> Option<(bool, DigestAlgorithm)> {
    [KeyType::Rsa, KeyType::EcP256].into_iter().find_map(|key| {
        [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ]
        .into_iter()
        .find(|&digest| signature_method_uri(key, digest) == uri)
        .map(|digest| (key == KeyType::Rsa, digest))
    })
}

/// Escapes character data.
pub(crate) fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
    out
}

/// Escapes an attribute value (written between double quotes).
pub(crate) fn escape_attr(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
    out
}

/// Base64 on one line, as AutoFirma writes certificates, signature values and data.
pub(crate) fn base64(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

/// Decodes Base64 text, ignoring whitespace.
pub(crate) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    Base64::decode_vec(&compact).ok()
}

/// Length in bytes of each half of a raw ECDSA signature.
fn ecdsa_field_len(key_type: KeyType) -> Option<usize> {
    match key_type {
        KeyType::Rsa => None,
        KeyType::EcP256 => Some(32),
        KeyType::EcP384 => Some(48),
    }
}

/// XMLDSig signature value from the raw signature of a [`crate::keystore::SigningKey`]:
/// ECDSA signatures go from DER to `r || s`; RSA ones are unchanged.
pub(crate) fn signature_value(key_type: KeyType, signature: &[u8]) -> Result<Vec<u8>> {
    let invalid = |e: &dyn std::fmt::Display| Error::Signing(e.to_string());
    Ok(match key_type {
        KeyType::Rsa => signature.to_vec(),
        KeyType::EcP256 => p256::ecdsa::Signature::from_der(signature)
            .map_err(|e| invalid(&e))?
            .to_bytes()
            .to_vec(),
        KeyType::EcP384 => p384::ecdsa::Signature::from_der(signature)
            .map_err(|e| invalid(&e))?
            .to_bytes()
            .to_vec(),
    })
}

/// DER ECDSA signature from an XMLDSig `r || s` value; `None` if its size does
/// not match the curve.
pub(crate) fn ecdsa_value_to_der(key_type: KeyType, value: &[u8]) -> Option<Vec<u8>> {
    if value.len() != 2 * ecdsa_field_len(key_type)? {
        return None;
    }
    Some(match key_type {
        KeyType::EcP256 => p256::ecdsa::Signature::from_slice(value)
            .ok()?
            .to_der()
            .as_bytes()
            .to_vec(),
        KeyType::EcP384 => p384::ecdsa::Signature::from_slice(value)
            .ok()?
            .to_der()
            .as_bytes()
            .to_vec(),
        KeyType::Rsa => return None,
    })
}

/// An XML document decoded to text, remembering how to encode it back.
#[derive(Debug, Clone)]
pub(crate) struct XmlText {
    /// The document, without byte order mark.
    pub text: String,
    encoding: &'static Encoding,
    bom: bool,
}

impl XmlText {
    /// A new UTF-8 document.
    pub fn utf8() -> Self {
        XmlText {
            text: String::new(),
            encoding: encoding_rs::UTF_8,
            bom: false,
        }
    }

    /// Name of the encoding of the output (`UTF-8`, `windows-1252`...).
    pub fn encoding_name(&self) -> &'static str {
        self.encoding.output_encoding().name()
    }

    /// Decodes `data` using its byte order mark or its XML declaration (UTF-8 by default).
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (encoding, bom) = match Encoding::for_bom(data) {
            Some((encoding, len)) => (encoding, len),
            None => (declared_encoding(data).unwrap_or(encoding_rs::UTF_8), 0),
        };
        let (text, had_errors) = encoding.decode_without_bom_handling(&data[bom..]);
        if had_errors {
            return Err(Error::InvalidXml(format!(
                "no está codificado en {}",
                encoding.name()
            )));
        }
        Ok(XmlText {
            text: text.into_owned(),
            encoding,
            bom: bom > 0,
        })
    }

    /// Encodes `text` (the document after a change) like the original.
    ///
    /// Characters the encoding cannot represent become character references.
    /// UTF-16 documents are written in UTF-8, since `encoding_rs` does not
    /// encode UTF-16; their declaration is updated.
    pub fn encode(&self, text: &str) -> Vec<u8> {
        let output = self.encoding.output_encoding();
        let mut out = Vec::with_capacity(text.len() + 3);
        if self.bom && self.encoding == encoding_rs::UTF_8 {
            out.extend_from_slice(b"\xef\xbb\xbf");
        }
        if output == self.encoding {
            out.extend_from_slice(&output.encode(text).0);
        } else {
            out.extend_from_slice(set_declared_encoding(text, "UTF-8").as_bytes());
        }
        out
    }
}

/// Encoding named in the XML declaration, if any.
fn declared_encoding(data: &[u8]) -> Option<&'static Encoding> {
    let head = &data[..data.len().min(256)];
    let head = std::str::from_utf8(head)
        .unwrap_or_else(|e| std::str::from_utf8(&head[..e.valid_up_to()]).unwrap_or(""));
    let declaration = head.strip_prefix("<?xml")?;
    let declaration = &declaration[..declaration.find("?>")?];
    let value = attribute_in(declaration, "encoding")?;
    Encoding::for_label(value.as_bytes())
}

/// Value of `name="..."` (or single quoted) in `text`.
fn attribute_in<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let rest = &text[text.find(name)? + name.len()..];
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let quote = rest.chars().next().filter(|c| matches!(c, '"' | '\''))?;
    let rest = &rest[1..];
    Some(&rest[..rest.find(quote)?])
}

/// `text` with the encoding of its XML declaration replaced.
fn set_declared_encoding(text: &str, encoding: &str) -> String {
    if let Some(rest) = text.strip_prefix("<?xml")
        && let Some(end) = rest.find("?>")
        && let Some(current) = attribute_in(&rest[..end], "encoding")
    {
        let start = 5 + rest.find(current).expect("value of the declaration");
        return format!(
            "{}{encoding}{}",
            &text[..start],
            &text[start + current.len()..]
        );
    }
    text.to_string()
}

/// Offset of the end tag (`</name>`) of the element in `range` of `text`.
pub(crate) fn end_tag_start(text: &str, range: std::ops::Range<usize>) -> Result<usize> {
    text[range.clone()]
        .rfind("</")
        .map(|i| range.start + i)
        .ok_or_else(|| Error::InvalidXml("falta la etiqueta de cierre".to_string()))
}

/// Offset just after the start tag of the element in `range` of `text`
/// (`>` may appear inside attribute values).
pub(crate) fn start_tag_end(text: &str, range: std::ops::Range<usize>) -> usize {
    let mut quote = None;
    for (i, c) in text[range.clone()].char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '>') => return range.start + i + 1,
            _ => {}
        }
    }
    range.end
}

/// Content of the element in `range` of `text`, between its start and end tags
/// (empty for `<name/>`).
pub(crate) fn inner_range(text: &str, range: std::ops::Range<usize>) -> std::ops::Range<usize> {
    if text[range.clone()].ends_with("/>") {
        return range.end..range.end;
    }
    let start = start_tag_end(text, range.clone());
    let end = end_tag_start(text, range).unwrap_or(start).max(start);
    start..end
}

/// Child elements of `id`.
pub(crate) fn child_elements(doc: &Document<'_>, id: NodeId) -> Vec<NodeId> {
    doc.children(id)
        .into_iter()
        .filter(|&child| matches!(doc.node_kind(child), Some(NodeKind::Element(_))))
        .collect()
}

/// First child element of `id` named `local` in namespace `ns`.
pub(crate) fn child(doc: &Document<'_>, id: NodeId, ns: &str, local: &str) -> Option<NodeId> {
    child_elements(doc, id)
        .into_iter()
        .find(|&child| is_element(doc, child, ns, local))
}

/// Child elements of `id` named `local` in namespace `ns`.
pub(crate) fn children(doc: &Document<'_>, id: NodeId, ns: &str, local: &str) -> Vec<NodeId> {
    child_elements(doc, id)
        .into_iter()
        .filter(|&child| is_element(doc, child, ns, local))
        .collect()
}

/// Whether `id` is the element `local` in namespace `ns`.
pub(crate) fn is_element(doc: &Document<'_>, id: NodeId, ns: &str, local: &str) -> bool {
    doc.element(id).is_some_and(|element| {
        element.name.local_name == local && element.name.namespace_uri.as_deref() == Some(ns)
    })
}

/// Every descendant element of `id` (not `id` itself) named `local` in `ns`.
pub(crate) fn descendants(doc: &Document<'_>, id: NodeId, ns: &str, local: &str) -> Vec<NodeId> {
    doc.descendants(id)
        .into_iter()
        .filter(|&node| node != id && is_element(doc, node, ns, local))
        .collect()
}

/// Text content of an element (its descendant text nodes), trimmed.
pub(crate) fn text(doc: &Document<'_>, id: NodeId) -> String {
    doc.text_content_deep(id).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_uris() {
        assert_eq!(
            signature_method_from_uri("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"),
            Some((true, DigestAlgorithm::Sha512))
        );
        assert_eq!(
            signature_method_from_uri("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"),
            Some((false, DigestAlgorithm::Sha256))
        );
        assert_eq!(
            digest_from_uri("http://www.w3.org/2001/04/xmldsig-more#sha384"),
            Some(DigestAlgorithm::Sha384)
        );
        assert_eq!(signature_method_from_uri("urn:x"), None);
    }

    #[test]
    fn base64_ignores_whitespace() {
        assert_eq!(decode_base64(" aG9s\nYQ== ").unwrap(), b"hola");
        assert!(decode_base64("a").is_none());
    }

    #[test]
    fn escaping() {
        assert_eq!(escape_text("a<b>&\"c\r"), "a&lt;b&gt;&amp;\"c&#13;");
        assert_eq!(escape_attr("a<\"&\n"), "a&lt;&quot;&amp;&#10;");
    }

    #[test]
    fn ecdsa_values() {
        let key = &crate::keystore::tests::load("ec.p12")[0];
        use crate::keystore::SigningKey;
        let der = key.sign_raw(DigestAlgorithm::Sha256, b"x").unwrap();
        let raw = signature_value(KeyType::EcP256, &der).unwrap();
        assert_eq!(raw.len(), 64);
        assert_eq!(ecdsa_value_to_der(KeyType::EcP256, &raw).unwrap(), der);
        assert!(ecdsa_value_to_der(KeyType::EcP384, &raw).is_none());
    }

    #[test]
    fn tag_offsets() {
        let text = r#"<r><a b="x>y">uno</a><c/></r>"#;
        let a = 3..21;
        assert_eq!(&text[a.clone()], r#"<a b="x>y">uno</a>"#);
        assert_eq!(&text[inner_range(text, a.clone())], "uno");
        assert_eq!(&text[end_tag_start(text, a).unwrap()..], "</a><c/></r>");
        assert!(inner_range(text, 21..25).is_empty());
    }

    #[test]
    fn decodes_and_encodes_like_the_original() {
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a>\xf1</a>";
        let xml = XmlText::decode(latin1).unwrap();
        assert_eq!(
            xml.text,
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a>ñ</a>"
        );
        // ISO-8859-1 is windows-1252 in encoding_rs; € is representable there.
        assert_eq!(xml.encode("<a>ñ\u{3a9}</a>"), b"<a>\xf1&#937;</a>".to_vec());

        let bom = XmlText::decode(b"\xef\xbb\xbf<a/>").unwrap();
        assert_eq!(bom.text, "<a/>");
        assert_eq!(bom.encode("<b/>"), b"\xef\xbb\xbf<b/>");

        let utf16: Vec<u8> = "\u{feff}<?xml version=\"1.0\" encoding=\"UTF-16\"?><a/>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let xml = XmlText::decode(&utf16).unwrap();
        assert_eq!(
            xml.encode(&xml.text),
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><a/>"
        );

        assert!(XmlText::decode(b"<a>\xff</a>").is_err());
    }
}
