//! XAdES co-signatures and counter-signatures, as AutoFirma's `XAdESCoSigner`
//! and `XAdESCounterSigner` make them, keeping the bytes of the existing
//! document:
//!
//! * a co-signature references the same data as the first signature of the
//!   document, with the same transforms. Enveloping data is copied into a
//!   `ds:Object` of the new signature. The new signature is the last child of
//!   the root element; a document whose root is a signature (enveloping) is
//!   first wrapped in an `AFIRMA` element.
//! * a counter-signature references the `SignatureValue` of the signature it
//!   signs and goes in its `xades:UnsignedSignatureProperties`, inside a
//!   `xades:CounterSignature`.

use bergshamra_c14n::C14nMode;
use bergshamra_xml::uppsala::{self, Document, NodeId};

use super::{
    DataFormat, NewSignature, PreparedXades, Reference, XadesParams, assemble,
    reference::{self, Ids, Transform},
};
use crate::{
    error::{Error, Result},
    keystore::SigningKey,
    multisign::CounterSignTarget,
    random,
    xml::{self, DSIG_NS, XADES_NS, XADES_OLD_NS, XmlText, escape_attr},
};

/// `Type` of the reference of a counter-signature to the signature it signs.
const COUNTERSIGNED_SIGNATURE_TYPE: &str = "http://uri.etsi.org/01903#CountersignedSignature";

fn invalid(message: &str) -> Error {
    Error::InvalidSignature(message.to_string())
}

/// Every `ds:Signature` of the document, in document order.
fn signatures(doc: &Document<'_>) -> Vec<NodeId> {
    doc.descendants(doc.root())
        .into_iter()
        .filter(|&node| xml::is_element(doc, node, DSIG_NS, "Signature"))
        .collect()
}

/// `QualifyingProperties` of a signature, in any XAdES namespace.
fn qualifying_properties(doc: &Document<'_>, signature: NodeId) -> Option<NodeId> {
    xml::children(doc, signature, DSIG_NS, "Object")
        .into_iter()
        .find_map(|object| {
            std::iter::once(XADES_NS)
                .chain(XADES_OLD_NS)
                .find_map(|ns| xml::child(doc, object, ns, "QualifyingProperties"))
        })
}

/// Fails if a signature has an archive timestamp, which a new signature would
/// invalidate (AutoFirma's `XAdESUtil.checkArchiveSignatures`).
fn check_archive(doc: &Document<'_>, signatures: &[NodeId]) -> Result<()> {
    let archived = signatures.iter().any(|&signature| {
        qualifying_properties(doc, signature).is_some_and(|qualifying| {
            doc.descendants(qualifying).into_iter().any(|node| {
                doc.element(node)
                    .is_some_and(|e| e.name.local_name == "ArchiveTimeStamp")
            })
        })
    });
    if archived {
        Err(Error::LongTermSignature)
    } else {
        Ok(())
    }
}

/// Signs the prepared signature and returns the document as text.
fn sign_text(
    prepared: PreparedXades,
    key: &dyn SigningKey,
    params: &XadesParams,
) -> Result<String> {
    let signature = key.sign_raw(params.digest, prepared.to_be_signed())?;
    prepared.finish_text(&signature)
}

/// Adds a signature over the data of the first signature of `xml` (co-signature).
///
/// `data` is the signed file of signatures that reference it outside the
/// document (as in ASiC containers).
pub fn cosign(
    xml: &[u8],
    data: Option<&[u8]>,
    key: &dyn SigningKey,
    params: &XadesParams,
) -> Result<Vec<u8>> {
    let source = XmlText::decode(xml)?;
    let text = &source.text;
    let doc = uppsala::parse(text).map_err(|e| Error::InvalidXml(e.to_string()))?;
    let ids = Ids::new(&doc);
    let all = signatures(&doc);
    check_archive(&doc, &all)?;
    let first = *all
        .first()
        .ok_or_else(|| invalid("el XML no contiene firmas"))?;
    let signed_info = xml::child(&doc, first, DSIG_NS, "SignedInfo")
        .ok_or_else(|| invalid("falta SignedInfo"))?;

    // References that are not data: to the KeyInfo and the SignedProperties.
    let key_info_id = xml::child(&doc, first, DSIG_NS, "KeyInfo")
        .and_then(|key_info| doc.get_attribute(key_info, "Id"))
        .map(str::to_string);
    let qualifying = qualifying_properties(&doc, first);
    let signed_properties_id = qualifying
        .and_then(|q| {
            xml::child_elements(&doc, q).into_iter().find(|&child| {
                doc.element(child)
                    .is_some_and(|e| e.name.local_name == "SignedProperties")
            })
        })
        .and_then(|properties| doc.get_attribute(properties, "Id"))
        .map(str::to_string);
    // DataObjectFormat of the original references, by reference id.
    let original_formats: Vec<(String, Option<String>, Option<String>)> = qualifying
        .map(|q| {
            doc.descendants(q)
                .into_iter()
                .filter(|&node| {
                    doc.element(node)
                        .is_some_and(|e| e.name.local_name == "DataObjectFormat")
                })
                .filter_map(|format| {
                    let target = doc.get_attribute(format, "ObjectReference")?;
                    let child_text = |local: &str| {
                        xml::child_elements(&doc, format)
                            .into_iter()
                            .find(|&c| doc.element(c).is_some_and(|e| e.name.local_name == local))
                            .map(|c| xml::text(&doc, c))
                            .filter(|t| !t.is_empty())
                    };
                    Some((
                        target.trim_start_matches('#').to_string(),
                        child_text("MimeType"),
                        child_text("Encoding"),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut new = NewSignature::new()?;
    for reference in xml::children(&doc, signed_info, DSIG_NS, "Reference") {
        let uri = doc.get_attribute(reference, "URI").unwrap_or_default();
        let type_uri = doc.get_attribute(reference, "Type").map(str::to_string);
        let fragment = uri.strip_prefix('#');
        if type_uri
            .as_deref()
            .is_some_and(|t| t.ends_with("#SignedProperties"))
            || (fragment.is_some()
                && (fragment == key_info_id.as_deref()
                    || fragment == signed_properties_id.as_deref()))
        {
            continue;
        }
        let transforms = match xml::child(&doc, reference, DSIG_NS, "Transforms") {
            Some(list) => xml::children(&doc, list, DSIG_NS, "Transform")
                .into_iter()
                .map(|transform| Transform::parse(&doc, transform))
                .collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        };
        let original = doc.get_attribute(reference, "Id").and_then(|id| {
            original_formats
                .iter()
                .find(|(target, _, _)| target == id)
                .map(|(_, mime, encoding)| (mime.clone(), encoding.clone()))
        });
        let (mut mime, mut encoding) = original.unwrap_or_default();
        let reference_id = format!("Reference-{}", random::uuid()?);

        // Enveloping: the data is a `ds:Object` of the signature; copy it.
        let object = fragment.and_then(|id| ids.get(id).ok()).filter(|&node| {
            doc.parent(node) == Some(first) && xml::is_element(&doc, node, DSIG_NS, "Object")
        });
        let new_uri = match object {
            Some(object) => {
                let range = doc
                    .node_range(object)
                    .ok_or_else(|| invalid("no se localizan los datos firmados"))?;
                let content = &text[xml::inner_range(text, range)];
                let object_mime = doc.get_attribute(object, "MimeType").map(str::to_string);
                let object_encoding = doc.get_attribute(object, "Encoding").map(str::to_string);
                mime = mime.or_else(|| object_mime.clone());
                encoding = encoding.or_else(|| object_encoding.clone());
                let object_id = format!("Object-{}", random::uuid()?);
                let mut attributes = String::new();
                if let Some(encoding) = &object_encoding {
                    attributes.push_str(&format!(r#" Encoding="{}""#, escape_attr(encoding)));
                }
                attributes.push_str(&format!(r#" Id="{object_id}""#));
                if let Some(mime) = &object_mime {
                    attributes.push_str(&format!(r#" MimeType="{}""#, escape_attr(mime)));
                }
                new.objects
                    .push(format!("<ds:Object{attributes}>{content}</ds:Object>"));
                format!("#{object_id}")
            }
            None => uri.to_string(),
        };
        if uri.is_empty() {
            mime = mime.or_else(|| Some("text/xml".to_string()));
        }
        new.references.push(Reference {
            id: Some(reference_id.clone()),
            type_uri,
            uri: new_uri,
            transforms,
        });
        new.formats.push(DataFormat {
            reference_id,
            mime: mime.unwrap_or_else(|| "application/octet-stream".to_string()),
            encoding,
        });
    }
    if new.references.is_empty() {
        return Err(invalid("la firma no referencia ningún dato"));
    }

    // Where the new signature goes.
    let root = doc
        .document_element()
        .ok_or_else(|| Error::InvalidXml("no tiene elemento raíz".to_string()))?;
    let range = doc
        .node_range(root)
        .ok_or_else(|| Error::InvalidXml("no se localiza el elemento raíz".to_string()))?;
    let (prefix, suffix) = if root == first {
        (
            format!(
                r#"{}<AFIRMA Id="AfirmaRoot-{}">{}"#,
                &text[..range.start],
                random::uuid()?,
                &text[range.clone()]
            ),
            format!("</AFIRMA>{}", &text[range.end..]),
        )
    } else {
        let end_tag = xml::end_tag_start(text, range)?;
        (text[..end_tag].to_string(), text[end_tag..].to_string())
    };

    let resolve = |_: &str| data.map(<[u8]>::to_vec).ok_or(Error::MissingSignedData);
    let external: reference::External<'_> = Some(&resolve);
    let prepared = assemble(
        &prefix,
        &suffix,
        source.clone(),
        new,
        key.certificate_chain(),
        key.key_type(),
        params,
        external,
    )?;
    let signed = sign_text(prepared, key, params)?;
    Ok(source.encode(&signed))
}

/// Counter-signs the signatures of `xml` chosen by `target`: every signature,
/// counter-signatures included ([`CounterSignTarget::Tree`]), or those without
/// counter-signatures ([`CounterSignTarget::Leafs`]).
pub fn countersign(
    xml: &[u8],
    target: CounterSignTarget,
    key: &dyn SigningKey,
    params: &XadesParams,
) -> Result<Vec<u8>> {
    let source = XmlText::decode(xml)?;
    let mut text = source.text.clone();

    // The signatures to counter-sign, by the id of their SignatureValue.
    let targets: Vec<String> = {
        let doc = uppsala::parse(&text).map_err(|e| Error::InvalidXml(e.to_string()))?;
        let all = signatures(&doc);
        if all.is_empty() {
            return Err(invalid("el XML no contiene firmas"));
        }
        check_archive(&doc, &all)?;
        all.into_iter()
            .filter(|&signature| {
                target == CounterSignTarget::Tree
                    || !doc.descendants(signature).into_iter().any(|node| {
                        node != signature && xml::is_element(&doc, node, DSIG_NS, "Signature")
                    })
            })
            .map(|signature| {
                xml::child(&doc, signature, DSIG_NS, "SignatureValue")
                    .and_then(|value| doc.get_attribute(value, "Id"))
                    .map(str::to_string)
                    .ok_or_else(|| {
                        Error::Unsupported(
                            "contrafirmar una firma cuyo SignatureValue no tiene identificador"
                                .to_string(),
                        )
                    })
            })
            .collect::<Result<_>>()?
    };

    // One at a time: each counter-signature is built in its final place.
    for value_id in targets {
        let doc = uppsala::parse(&text).map_err(|e| Error::InvalidXml(e.to_string()))?;
        let ids = Ids::new(&doc);
        let value = ids.get(&value_id)?;
        let signature = doc
            .parent(value)
            .ok_or_else(|| invalid("SignatureValue sin firma"))?;
        let qualifying = qualifying_properties(&doc, signature).ok_or_else(|| {
            Error::Unsupported("contrafirmar una firma XMLDSig sin propiedades XAdES".to_string())
        })?;
        let ns = doc
            .element(qualifying)
            .and_then(|e| e.name.namespace_uri.as_deref())
            .unwrap_or(XADES_NS)
            .to_string();

        let mut new = NewSignature::new()?;
        let reference_id = format!("Reference-{}", random::uuid()?);
        new.references.push(Reference {
            id: Some(reference_id.clone()),
            // XAdES 1.1.1 and 1.2.2 do not define the type.
            type_uri: (!XADES_OLD_NS.contains(&ns.as_str()))
                .then(|| COUNTERSIGNED_SIGNATURE_TYPE.to_string()),
            uri: format!("#{value_id}"),
            transforms: vec![Transform::C14n(C14nMode::Inclusive, Vec::new())],
        });
        new.formats.push(DataFormat {
            reference_id,
            mime: "text/xml".to_string(),
            encoding: Some(source.encoding_name().to_string()),
        });

        // Inside UnsignedSignatureProperties, creating it if needed.
        let declaration = format!(r#" xmlns:xades="{}""#, escape_attr(&ns));
        let unsigned = xml::child(&doc, qualifying, &ns, "UnsignedProperties");
        let unsigned_signature = unsigned
            .and_then(|unsigned| xml::child(&doc, unsigned, &ns, "UnsignedSignatureProperties"));
        let (container, open, close) = match (unsigned, unsigned_signature) {
            (_, Some(properties)) => (
                properties,
                format!("<xades:CounterSignature{declaration}>"),
                "</xades:CounterSignature>".to_string(),
            ),
            (Some(unsigned), None) => (
                unsigned,
                format!("<xades:UnsignedSignatureProperties{declaration}><xades:CounterSignature>"),
                "</xades:CounterSignature></xades:UnsignedSignatureProperties>".to_string(),
            ),
            (None, None) => (
                qualifying,
                format!(
                    "<xades:UnsignedProperties{declaration}><xades:UnsignedSignatureProperties><xades:CounterSignature>"
                ),
                "</xades:CounterSignature></xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
                    .to_string(),
            ),
        };
        let range = doc
            .node_range(container)
            .ok_or_else(|| invalid("no se localiza la firma"))?;
        if text[range.clone()].ends_with("/>") {
            return Err(Error::Unsupported("propiedades XAdES vacías".to_string()));
        }
        let at = xml::end_tag_start(&text, range)?;
        let prefix = format!("{}{open}", &text[..at]);
        let suffix = format!("{close}{}", &text[at..]);
        let prepared = assemble(
            &prefix,
            &suffix,
            source.clone(),
            new,
            key.certificate_chain(),
            key.key_type(),
            params,
            None,
        )?;
        text = sign_text(prepared, key, params)?;
    }
    Ok(source.encode(&text))
}
