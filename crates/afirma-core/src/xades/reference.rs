//! Processing of XMLDSig references: dereferencing the URI, the transforms and
//! the digest. Shared by signing (to compute `DigestValue`) and verification.
//!
//! The transforms are ours, on top of `bergshamra-c14n`: enveloped signature,
//! Base64, the canonicalizations, and the XPath filters equivalent to the
//! enveloped transform (`not(ancestor-or-self::ds:Signature)`, AutoFirma's),
//! which are the only XPath expressions accepted.

use std::collections::HashMap;

use bergshamra_c14n::C14nMode;
use bergshamra_xml::{
    NodeSet,
    uppsala::{Document, NodeId, NodeKind},
};

use super::super::xml::{self, DSIG_NS, uri};
use crate::{
    digest::DigestAlgorithm,
    error::{Error, Result},
};

/// A transform of a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Transform {
    /// Removes the signature that contains the reference.
    Enveloped,
    /// Removes every `ds:Signature` (AutoFirma's XPath filter).
    NotSignatures,
    /// Canonicalization, with the `InclusiveNamespaces` prefixes of exclusive C14N.
    C14n(C14nMode, Vec<String>),
    /// Base64 decoding.
    Base64,
}

impl Transform {
    /// `ds:Transform` element.
    pub fn to_xml(&self) -> String {
        match self {
            Transform::Enveloped => format!(r#"<ds:Transform Algorithm="{}"/>"#, uri::ENVELOPED),
            Transform::NotSignatures => format!(
                r#"<ds:Transform Algorithm="{}"><ds:XPath xmlns:ds="{DSIG_NS}">not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform>"#,
                uri::XPATH
            ),
            Transform::C14n(mode, _) => format!(r#"<ds:Transform Algorithm="{}"/>"#, mode.uri()),
            Transform::Base64 => format!(r#"<ds:Transform Algorithm="{}"/>"#, uri::BASE64),
        }
    }

    /// Reads a `ds:Transform` element.
    pub fn parse(doc: &Document<'_>, transform: NodeId) -> Result<Self> {
        let algorithm = doc
            .get_attribute(transform, "Algorithm")
            .unwrap_or_default();
        match algorithm {
            uri::ENVELOPED => Ok(Transform::Enveloped),
            uri::BASE64 => Ok(Transform::Base64),
            uri::XPATH => {
                let xpath = xml::child(doc, transform, DSIG_NS, "XPath")
                    .ok_or_else(|| invalid("transformada XPath sin expresión"))?;
                parse_xpath(doc, xpath)
            }
            _ => {
                let mode = C14nMode::from_uri(algorithm)
                    .ok_or_else(|| Error::Unsupported(format!("transformada XML {algorithm}")))?;
                Ok(Transform::C14n(mode, inclusive_prefixes(doc, transform)))
            }
        }
    }
}

/// `InclusiveNamespaces PrefixList` of an exclusive canonicalization element.
pub(crate) fn inclusive_prefixes(doc: &Document<'_>, method: NodeId) -> Vec<String> {
    xml::child_elements(doc, method)
        .into_iter()
        .find(|&child| {
            doc.element(child)
                .is_some_and(|e| e.name.local_name == "InclusiveNamespaces")
        })
        .and_then(|list| doc.get_attribute(list, "PrefixList"))
        .map(|list| {
            list.split_whitespace()
                .map(|prefix| match prefix {
                    "#default" => String::new(),
                    prefix => prefix.to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Accepts the XPath expressions that select the document without signatures:
/// `not(ancestor-or-self::P:Signature)` with `P` bound to the XMLDSig namespace.
fn parse_xpath(doc: &Document<'_>, xpath: NodeId) -> Result<Transform> {
    let expression: String = doc
        .text_content_deep(xpath)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let prefix = expression
        .strip_prefix("not(ancestor-or-self::")
        .and_then(|rest| rest.strip_suffix(":Signature)"));
    let bound_to_dsig = prefix.is_some_and(|prefix| {
        std::iter::once(xpath)
            .chain(doc.ancestors(xpath))
            .filter_map(|id| doc.element(id))
            .find_map(|element| {
                element
                    .namespace_declarations
                    .iter()
                    .find(|(p, _)| p == prefix)
                    .map(|(_, ns)| ns.as_ref() == DSIG_NS)
            })
            .unwrap_or(false)
    });
    if bound_to_dsig {
        Ok(Transform::NotSignatures)
    } else {
        Err(Error::Unsupported(format!(
            "transformada XPath «{expression}»"
        )))
    }
}

fn invalid(message: &str) -> Error {
    Error::InvalidSignature(message.to_string())
}

/// Elements of a document by their `Id` (also `ID` and `id`) attribute.
#[derive(Debug, Default)]
pub(crate) struct Ids {
    /// `None` when several elements share the id.
    map: HashMap<String, Option<NodeId>>,
}

impl Ids {
    pub fn new(doc: &Document<'_>) -> Self {
        let mut map: HashMap<String, Option<NodeId>> = HashMap::new();
        for node in doc.descendants(doc.root()) {
            let Some(element) = doc.element(node) else {
                continue;
            };
            for attribute in &element.attributes {
                if attribute.name.namespace_uri.is_none()
                    && matches!(attribute.name.local_name.as_ref(), "Id" | "ID" | "id")
                {
                    map.entry(attribute.value.to_string())
                        .and_modify(|entry| *entry = None)
                        .or_insert(Some(node));
                }
            }
        }
        Ids { map }
    }

    /// Element with `id`. Ambiguous ids are an error, so a reference cannot be
    /// redirected to another element with the same id (wrapping attacks).
    pub fn get(&self, id: &str) -> Result<NodeId> {
        match self.map.get(id) {
            Some(Some(node)) => Ok(*node),
            Some(None) => Err(invalid(&format!("identificador «{id}» duplicado"))),
            None => Err(invalid(&format!("no se encuentra el elemento «{id}»"))),
        }
    }
}

/// Data flowing through the transforms.
enum Data {
    Nodes(NodeSet),
    Octets(Vec<u8>),
}

/// Data of a reference whose URI is not in the document (detached signatures):
/// the external file the caller provides.
pub(crate) type External<'a> = Option<&'a [u8]>;

/// Digest of a reference: dereferences `uri` in `doc`, applies `transforms`
/// and hashes the result. `signature` is the `ds:Signature` element (for the
/// enveloped transform).
pub(crate) fn digest(
    doc: &Document<'_>,
    ids: &Ids,
    signature: NodeId,
    uri: &str,
    transforms: &[Transform],
    algorithm: DigestAlgorithm,
    external: External<'_>,
) -> Result<Vec<u8>> {
    let mut data = dereference(doc, ids, uri, external)?;
    for transform in transforms {
        data = apply(doc, signature, transform, data)?;
    }
    let octets = match data {
        Data::Octets(octets) => octets,
        // Node sets are converted to octets with inclusive C14N.
        Data::Nodes(set) => canonicalize(doc, C14nMode::Inclusive, &set, &[])?,
    };
    Ok(algorithm.digest(&octets))
}

fn dereference(doc: &Document<'_>, ids: &Ids, uri: &str, external: External<'_>) -> Result<Data> {
    if uri.is_empty() {
        return Ok(Data::Nodes(NodeSet::all_without_comments(doc)));
    }
    let Some(fragment) = uri.strip_prefix('#') else {
        return external
            .map(|data| Data::Octets(data.to_vec()))
            .ok_or(Error::MissingSignedData);
    };
    if fragment == "xpointer(/)" {
        return Ok(Data::Nodes(NodeSet::all(doc)));
    }
    if let Some(id) = fragment
        .strip_prefix("xpointer(id(")
        .and_then(|rest| rest.strip_suffix("))"))
    {
        let id = id.trim_matches(|c| c == '\'' || c == '"');
        return Ok(Data::Nodes(NodeSet::tree_with_comments(ids.get(id)?, doc)));
    }
    Ok(Data::Nodes(NodeSet::tree_without_comments(
        ids.get(fragment)?,
        doc,
    )))
}

fn apply(doc: &Document<'_>, signature: NodeId, transform: &Transform, data: Data) -> Result<Data> {
    match (transform, data) {
        (Transform::Enveloped, Data::Nodes(mut set)) => {
            remove_subtree(doc, signature, &mut set);
            Ok(Data::Nodes(set))
        }
        (Transform::NotSignatures, Data::Nodes(mut set)) => {
            for node in doc.descendants(doc.root()) {
                if xml::is_element(doc, node, DSIG_NS, "Signature") {
                    remove_subtree(doc, node, &mut set);
                }
            }
            Ok(Data::Nodes(set))
        }
        (Transform::C14n(mode, prefixes), Data::Nodes(set)) => {
            Ok(Data::Octets(canonicalize(doc, *mode, &set, prefixes)?))
        }
        (Transform::C14n(mode, prefixes), Data::Octets(octets)) => {
            let text = std::str::from_utf8(&octets)
                .map_err(|_| invalid("los datos transformados no son XML UTF-8"))?;
            bergshamra_c14n::canonicalize(text, *mode, None, prefixes)
                .map(Data::Octets)
                .map_err(|e| Error::InvalidXml(e.to_string()))
        }
        (Transform::Base64, Data::Nodes(set)) => {
            // The string value of the node set: its text nodes, in document order.
            let mut text = String::new();
            for node in doc.descendants(doc.root()) {
                if set.contains_id(node)
                    && let Some(NodeKind::Text(value) | NodeKind::CData(value)) =
                        doc.node_kind(node)
                {
                    text.push_str(value);
                }
            }
            decode_base64(&text)
        }
        (Transform::Base64, Data::Octets(octets)) => {
            decode_base64(&String::from_utf8_lossy(&octets))
        }
        (Transform::NotSignatures, Data::Octets(octets)) => {
            // AutoFirma filters after canonicalizing: parse the octets again.
            let text = std::str::from_utf8(&octets)
                .map_err(|_| invalid("los datos transformados no son XML UTF-8"))?;
            let parsed = bergshamra_xml::uppsala::parse(text)
                .map_err(|e| Error::InvalidXml(e.to_string()))?;
            let Data::Nodes(set) = apply(
                &parsed,
                parsed.root(),
                transform,
                Data::Nodes(NodeSet::all(&parsed)),
            )?
            else {
                unreachable!("node sets stay node sets");
            };
            canonicalize(&parsed, C14nMode::Inclusive, &set, &[]).map(Data::Octets)
        }
        (Transform::Enveloped, Data::Octets(_)) => {
            Err(invalid("la transformada enveloped necesita datos XML"))
        }
    }
}

fn decode_base64(text: &str) -> Result<Data> {
    xml::decode_base64(text)
        .map(Data::Octets)
        .ok_or_else(|| invalid("los datos firmados no están en Base64"))
}

fn remove_subtree(doc: &Document<'_>, node: NodeId, set: &mut NodeSet) {
    set.remove_id(node);
    for descendant in doc.descendants(node) {
        set.remove_id(descendant);
    }
}

/// Canonical form of the nodes of `set`.
pub(crate) fn canonicalize(
    doc: &Document<'_>,
    mode: C14nMode,
    set: &NodeSet,
    prefixes: &[String],
) -> Result<Vec<u8>> {
    bergshamra_c14n::canonicalize_doc(doc, mode, Some(set), prefixes)
        .map_err(|e| Error::InvalidXml(e.to_string()))
}

/// Canonical form of the subtree of `element` (without comments, unless the mode keeps them).
pub(crate) fn canonicalize_element(
    doc: &Document<'_>,
    element: NodeId,
    mode: C14nMode,
    prefixes: &[String],
) -> Result<Vec<u8>> {
    let set = if mode.with_comments() {
        NodeSet::tree_with_comments(element, doc)
    } else {
        NodeSet::tree_without_comments(element, doc)
    };
    canonicalize(doc, mode, &set, prefixes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bergshamra_xml::uppsala;

    const DOC: &str = r#"<r xmlns="urn:x" Id="root"><a Id="a">uno<!-- c --></a><b Id="b">aG9sYQ==</b><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="s"><ds:X/></ds:Signature></r>"#;

    fn run(uri: &str, transforms: &[Transform]) -> Vec<u8> {
        let doc = uppsala::parse(DOC).unwrap();
        let ids = Ids::new(&doc);
        let signature = ids.get("s").unwrap();
        let mut data = dereference(&doc, &ids, uri, None).unwrap();
        for transform in transforms {
            data = apply(&doc, signature, transform, data).unwrap();
        }
        match data {
            Data::Octets(octets) => octets,
            Data::Nodes(set) => canonicalize(&doc, C14nMode::Inclusive, &set, &[]).unwrap(),
        }
    }

    #[test]
    fn enveloped_and_xpath_remove_the_signature() {
        let expected = r#"<r xmlns="urn:x" Id="root"><a Id="a">uno</a><b Id="b">aG9sYQ==</b></r>"#;
        for transforms in [
            vec![Transform::Enveloped],
            vec![Transform::NotSignatures],
            vec![
                Transform::Enveloped,
                Transform::C14n(C14nMode::Inclusive, vec![]),
            ],
            // AutoFirma's chain: the XPath filter gets octets.
            vec![
                Transform::Enveloped,
                Transform::C14n(C14nMode::Inclusive, vec![]),
                Transform::NotSignatures,
            ],
        ] {
            assert_eq!(String::from_utf8(run("", &transforms)).unwrap(), expected);
        }
        // #root: the same subtree.
        assert_eq!(
            String::from_utf8(run("#root", &[Transform::Enveloped])).unwrap(),
            expected
        );
    }

    #[test]
    fn id_references_inherit_namespaces() {
        assert_eq!(
            String::from_utf8(run("#a", &[])).unwrap(),
            r#"<a xmlns="urn:x" Id="a">uno</a>"#
        );
        assert_eq!(run("#b", &[Transform::Base64]), b"hola");
    }

    #[test]
    fn rejects_duplicated_ids_and_external_data() {
        let doc = uppsala::parse(r#"<r><a Id="x"/><b Id="x"/></r>"#).unwrap();
        let ids = Ids::new(&doc);
        assert!(ids.get("x").is_err());
        assert!(matches!(
            dereference(&doc, &ids, "doc.txt", None),
            Err(Error::MissingSignedData)
        ));
        assert!(matches!(
            dereference(&doc, &ids, "doc.txt", Some(b"x")),
            Ok(Data::Octets(_))
        ));
    }

    #[test]
    fn xpath_filters() {
        let parse = |xpath: &str| {
            let text = format!(
                r#"<ds:Transform xmlns:ds="{DSIG_NS}" xmlns:o="urn:o" Algorithm="{}"><ds:XPath>{xpath}</ds:XPath></ds:Transform>"#,
                uri::XPATH
            );
            let doc = uppsala::parse(&text).unwrap();
            Transform::parse(&doc, doc.document_element().unwrap())
        };
        assert_eq!(
            parse("not(ancestor-or-self::ds:Signature)").unwrap(),
            Transform::NotSignatures
        );
        assert_eq!(
            parse(" not( ancestor-or-self::ds:Signature ) ").unwrap(),
            Transform::NotSignatures
        );
        assert!(parse("not(ancestor-or-self::o:Signature)").is_err());
        assert!(parse("self::text()").is_err());
    }
}
