//! Processing of XMLDSig references: dereferencing the URI, the transforms and
//! the digest. Shared by signing (to compute `DigestValue`) and verification.
//!
//! The transforms are ours, on top of `bergshamra-c14n`: enveloped signature,
//! Base64, the canonicalizations, the XPath filters equivalent to the
//! enveloped transform (`not(ancestor-or-self::ds:Signature)`, AutoFirma's),
//! which are the only XPath expressions accepted, and the OPC relationship
//! transform of OOXML packages (ISO/IEC 29500-2, 13.2.4.24).

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
    /// OPC relationship transform: the relationships with these `Id`s or `Type`s.
    Relationships {
        /// `SourceId` of the `RelationshipReference`s.
        ids: Vec<String>,
        /// `SourceType` of the `RelationshipsGroupReference`s.
        types: Vec<String>,
    },
}

/// OPC relationship transform.
pub(crate) const RELATIONSHIP_TRANSFORM: &str =
    "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";
/// OPC digital signature namespace (`mdssi`).
pub(crate) const MDSSI_NS: &str =
    "http://schemas.openxmlformats.org/package/2006/digital-signature";
/// Exclusive C14N namespace (`InclusiveNamespaces`).
const EXC_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

impl Transform {
    /// `Transform` element; `p` is the prefix of the XMLDSig namespace (`ds:`,
    /// or empty for the default namespace).
    pub fn to_xml(&self, p: &str) -> String {
        match self {
            Transform::Enveloped => format!(r#"<{p}Transform Algorithm="{}"/>"#, uri::ENVELOPED),
            Transform::NotSignatures => format!(
                r#"<{p}Transform Algorithm="{}"><{p}XPath xmlns:ds="{DSIG_NS}">not(ancestor-or-self::ds:Signature)</{p}XPath></{p}Transform>"#,
                uri::XPATH
            ),
            Transform::C14n(mode, prefixes) if prefixes.is_empty() => {
                format!(r#"<{p}Transform Algorithm="{}"/>"#, mode.uri())
            }
            Transform::C14n(mode, prefixes) => {
                let list: Vec<&str> = prefixes
                    .iter()
                    .map(|p| if p.is_empty() { "#default" } else { p })
                    .collect();
                format!(
                    r#"<{p}Transform Algorithm="{}"><ec:InclusiveNamespaces xmlns:ec="{EXC_C14N_NS}" PrefixList="{}"/></{p}Transform>"#,
                    mode.uri(),
                    xml::escape_attr(&list.join(" "))
                )
            }
            Transform::Base64 => format!(r#"<{p}Transform Algorithm="{}"/>"#, uri::BASE64),
            Transform::Relationships { ids, types } => {
                let mut out = format!(r#"<{p}Transform Algorithm="{RELATIONSHIP_TRANSFORM}">"#);
                for id in ids {
                    out.push_str(&format!(
                        r#"<mdssi:RelationshipReference xmlns:mdssi="{MDSSI_NS}" SourceId="{}"/>"#,
                        xml::escape_attr(id)
                    ));
                }
                for source_type in types {
                    out.push_str(&format!(
                        r#"<mdssi:RelationshipsGroupReference xmlns:mdssi="{MDSSI_NS}" SourceType="{}"/>"#,
                        xml::escape_attr(source_type)
                    ));
                }
                out.push_str(&format!("</{p}Transform>"));
                out
            }
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
            RELATIONSHIP_TRANSFORM => {
                let values = |local: &str, attribute: &str| {
                    xml::children(doc, transform, MDSSI_NS, local)
                        .into_iter()
                        .filter_map(|node| doc.get_attribute(node, attribute))
                        .map(str::to_string)
                        .collect()
                };
                Ok(Transform::Relationships {
                    ids: values("RelationshipReference", "SourceId"),
                    types: values("RelationshipsGroupReference", "SourceType"),
                })
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

/// Resolves the references whose URI is not in the document (detached
/// signatures, parts of ODF and OOXML packages) to the bytes they point to.
pub(crate) type External<'a> = Option<&'a dyn Fn(&str) -> Result<Vec<u8>>>;

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
        let resolve = external.ok_or(Error::MissingSignedData)?;
        return resolve(uri).map(Data::Octets);
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
        (Transform::Relationships { ids, types }, Data::Octets(octets)) => {
            relationships(&octets, ids, types).map(Data::Octets)
        }
        (Transform::Relationships { .. }, Data::Nodes(_)) => Err(invalid(
            "la transformada de relaciones necesita una parte del paquete",
        )),
    }
}

/// OPC relationship transform: keeps the `Relationship` elements selected by
/// `Id` or `Type`, adds the default `TargetMode="Internal"`, sorts them by `Id`
/// and drops everything else inside the root. The output is XML, to be
/// canonicalized by the next transform.
fn relationships(octets: &[u8], ids: &[String], types: &[String]) -> Result<Vec<u8>> {
    let source = xml::XmlText::decode(octets)?;
    let doc = bergshamra_xml::uppsala::parse(&source.text)
        .map_err(|e| Error::InvalidXml(e.to_string()))?;
    let root = doc
        .document_element()
        .ok_or_else(|| invalid("relaciones sin elemento raíz"))?;
    let root_element = doc.element(root).expect("document element");
    let mut kept: Vec<(String, String)> = xml::child_elements(&doc, root)
        .into_iter()
        .filter_map(|child| {
            let element = doc.element(child)?;
            let id = element.get_attribute("Id").unwrap_or_default();
            let relationship_type = element.get_attribute("Type").unwrap_or_default();
            let selected =
                ids.iter().any(|i| i == id) || types.iter().any(|t| t == relationship_type);
            if !selected || element.name.local_name != "Relationship" {
                return None;
            }
            let mut out = format!("<{}", element.name.prefixed_name());
            write_declarations_and_attributes(&mut out, element);
            if element.get_attribute("TargetMode").is_none() {
                out.push_str(r#" TargetMode="Internal""#);
            }
            out.push_str("/>");
            Some((id.to_string(), out))
        })
        .collect();
    kept.sort_by(|a, b| a.0.cmp(&b.0));

    let name = root_element.name.prefixed_name();
    let mut out = format!("<{name}");
    write_declarations_and_attributes(&mut out, root_element);
    out.push('>');
    for (_, relationship) in kept {
        out.push_str(&relationship);
    }
    out.push_str(&format!("</{name}>"));
    Ok(out.into_bytes())
}

/// Writes the namespace declarations and attributes of `element`, escaped.
fn write_declarations_and_attributes(
    out: &mut String,
    element: &bergshamra_xml::uppsala::Element<'_>,
) {
    for (prefix, namespace) in &element.namespace_declarations {
        if prefix.is_empty() {
            out.push_str(&format!(r#" xmlns="{}""#, xml::escape_attr(namespace)));
        } else {
            out.push_str(&format!(
                r#" xmlns:{prefix}="{}""#,
                xml::escape_attr(namespace)
            ));
        }
    }
    for attribute in &element.attributes {
        out.push_str(&format!(
            r#" {}="{}""#,
            attribute.name.prefixed_name(),
            xml::escape_attr(&attribute.value)
        ));
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
        let resolve = |_: &str| Ok(b"x".to_vec());
        assert!(matches!(
            dereference(&doc, &ids, "doc.txt", Some(&resolve)),
            Ok(Data::Octets(_))
        ));
    }

    #[test]
    fn relationship_transform() {
        let rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
  <Relationship Id="rId2" Type="urn:t" Target="a&amp;b.xml"/>
  <Relationship Id="rId1" Type="urn:office" Target="word/document.xml" TargetMode="External"/>
</Relationships>"#;
        let transform = Transform::Relationships {
            ids: vec!["rId1".to_string()],
            types: vec!["urn:t".to_string()],
        };
        let canonical = apply(
            &bergshamra_xml::uppsala::parse("<x/>").unwrap(),
            NodeId::new(0),
            &Transform::C14n(C14nMode::Inclusive, vec![]),
            apply(
                &bergshamra_xml::uppsala::parse("<x/>").unwrap(),
                NodeId::new(0),
                &transform,
                Data::Octets(rels.to_vec()),
            )
            .unwrap(),
        )
        .unwrap();
        let Data::Octets(canonical) = canonical else {
            panic!("octets expected");
        };
        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="word/document.xml" TargetMode="External" Type="urn:office"></Relationship><Relationship Id="rId2" Target="a&amp;b.xml" TargetMode="Internal" Type="urn:t"></Relationship></Relationships>"#
        );

        // Written and read back.
        let text = format!(
            r#"<ds:Transforms xmlns:ds="{DSIG_NS}">{}</ds:Transforms>"#,
            transform.to_xml("ds:")
        );
        let doc = bergshamra_xml::uppsala::parse(&text).unwrap();
        let node = xml::child_elements(&doc, doc.document_element().unwrap())[0];
        assert_eq!(Transform::parse(&doc, node).unwrap(), transform);
    }

    #[test]
    fn exclusive_prefixes_round_trip() {
        let transform = Transform::C14n(
            C14nMode::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#").unwrap(),
            vec![String::new(), "ds".to_string()],
        );
        let text = format!(
            r#"<ds:Transforms xmlns:ds="{DSIG_NS}">{}</ds:Transforms>"#,
            transform.to_xml("ds:")
        );
        let doc = bergshamra_xml::uppsala::parse(&text).unwrap();
        let node = xml::child_elements(&doc, doc.document_element().unwrap())[0];
        assert_eq!(Transform::parse(&doc, node).unwrap(), transform);
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
