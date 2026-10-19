//! Verification of the signatures of a PDF.

use lopdf::{Dictionary, Document, Object, ObjectId, xref::XrefEntry};
use serde::{Deserialize, Serialize};

use super::{CertificationLevel, dict_get, form_fields, load, pdf};
use crate::{
    cades::{self, SignerReport, SignerStatus},
    error::{Error, Result},
    tsp,
};

/// Result of verifying one signature of a PDF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfSignatureReport {
    /// Name of the signature field.
    pub field: String,
    /// `/SubFilter` (`ETSI.CAdES.detached`, `adbe.pkcs7.detached`...).
    pub sub_filter: String,
    /// Signing time claimed in `/M`, seconds since the Unix epoch.
    pub claimed_time: Option<i64>,
    /// `/Reason`.
    pub reason: Option<String>,
    /// `/Location`.
    pub location: Option<String>,
    /// The signature certifies the document (DocMDP), with this level.
    pub certification: Option<CertificationLevel>,
    /// The signature covers the whole document. When `false`, the document
    /// was changed after signing (for instance, by a later signature).
    pub covers_whole_document: bool,
    /// Size of the revision this signature covers.
    pub revision_length: usize,
    /// Verification of the CMS signature over the signed bytes.
    pub signer: SignerReport,
}

/// Result of verifying a PDF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfVerifyReport {
    /// One report per signed signature field, in document order.
    pub signatures: Vec<PdfSignatureReport>,
}

impl PdfVerifyReport {
    /// Whether there is at least one signature and every one is valid.
    pub fn is_valid(&self) -> bool {
        !self.signatures.is_empty()
            && self
                .signatures
                .iter()
                .all(|s| s.signer.status == SignerStatus::Valid)
    }
}

/// Verifies the integrity of every signature of `pdf`. Certificate trust and
/// revocation are not checked.
pub fn verify(pdf: &[u8], password: Option<&str>) -> Result<PdfVerifyReport> {
    let doc = load(pdf, password)?;
    let mut signatures = Vec::new();
    for (field, dict) in form_fields(&doc) {
        if dict_get(&doc, dict, b"FT").and_then(|ft| ft.as_name().ok()) != Some(b"Sig") {
            continue;
        }
        let Some(signature) = dict_get(&doc, dict, b"V").and_then(|v| v.as_dict().ok()) else {
            continue;
        };
        let signature = match dict.get(b"V") {
            Ok(Object::Reference(id)) => decrypt_text_entries(&doc, pdf, *id, signature),
            _ => signature.clone(),
        };
        signatures.push(verify_signature(&doc, pdf, field, &signature)?);
    }
    // Sorted by revision, oldest first.
    signatures.sort_by_key(|s| s.revision_length);
    Ok(PdfVerifyReport { signatures })
}

fn verify_signature(
    doc: &Document,
    pdf: &[u8],
    field: String,
    signature: &lopdf::Dictionary,
) -> Result<PdfSignatureReport> {
    let invalid = |msg: &str| Error::InvalidSignature(format!("{field}: {msg}"));
    let text = |key: &[u8]| {
        dict_get(doc, signature, key)
            .and_then(|o| o.as_str().ok())
            .map(pdf::decode_text_string)
    };
    let sub_filter = dict_get(doc, signature, b"SubFilter")
        .and_then(|o| o.as_name().ok())
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .unwrap_or_default();

    let byte_range: Vec<usize> = dict_get(doc, signature, b"ByteRange")
        .and_then(|o| o.as_array().ok())
        .map(|a| {
            a.iter()
                .filter_map(|o| o.as_i64().ok().and_then(|v| usize::try_from(v).ok()))
                .collect()
        })
        .unwrap_or_default();
    let [start1, len1, start2, len2] = byte_range[..] else {
        return Err(invalid("ByteRange no válido"));
    };
    let end2 = start2
        .checked_add(len2)
        .ok_or_else(|| invalid("ByteRange no válido"))?;
    if start1 != 0 || len1 >= start2 || end2 > pdf.len() {
        return Err(invalid("ByteRange fuera del documento"));
    }

    // The gap must be exactly the /Contents hex string. Read it from the file:
    // lopdf would try to decrypt it in encrypted documents.
    let gap = &pdf[len1..start2];
    let hex = gap
        .strip_prefix(b"<")
        .and_then(|g| g.strip_suffix(b">"))
        .ok_or_else(|| invalid("el hueco del ByteRange no es /Contents"))?;
    let cms = decode_hex(hex).ok_or_else(|| invalid("/Contents no es hexadecimal"))?;
    let cms = der_prefix(&cms).ok_or_else(|| invalid("/Contents no contiene una firma CMS"))?;

    let mut signed = Vec::with_capacity(len1 + len2);
    signed.extend_from_slice(&pdf[..len1]);
    signed.extend_from_slice(&pdf[start2..end2]);

    let certification = dict_get(doc, signature, b"Reference")
        .and_then(|o| o.as_array().ok())
        .and_then(|refs| {
            refs.iter().find_map(|r| {
                let r = super::resolve(doc, r).as_dict().ok()?;
                (dict_get(doc, r, b"TransformMethod")?.as_name().ok()? == b"DocMDP").then(|| {
                    let p = dict_get(doc, r, b"TransformParams")
                        .and_then(|p| p.as_dict().ok())
                        .and_then(|p| dict_get(doc, p, b"P"))
                        .and_then(|p| p.as_i64().ok())
                        .unwrap_or(2);
                    CertificationLevel::from_permissions(p)
                })
            })
        });

    // Document timestamps (ETSI.RFC3161) hold a timestamp token over the
    // signed bytes; signatures, a CMS signature of them.
    let document_timestamp = sub_filter == "ETSI.RFC3161";
    let report = cades::verify(cms, (!document_timestamp).then_some(&signed[..]))?;
    let mut signer = report
        .signers
        .into_iter()
        .next()
        .ok_or_else(|| invalid("la firma CMS no tiene firmantes"))?;
    if document_timestamp {
        let timestamp = tsp::verify_token(cms, |digest| Ok(digest.digest(&signed)));
        signer.signing_time = timestamp.time;
        signer.status = timestamp.status.clone();
        signer.timestamps = vec![timestamp];
    }

    Ok(PdfSignatureReport {
        field,
        sub_filter,
        claimed_time: text(b"M").and_then(|m| pdf::parse_pdf_date(&m)),
        reason: text(b"Reason"),
        location: text(b"Location"),
        certification,
        covers_whole_document: covers_rest(pdf, end2),
        revision_length: end2,
        signer,
    })
}

/// Text entries of a signature dictionary of an encrypted PDF.
///
/// lopdf also tries to decrypt `/Contents`, which is never encrypted; with AES
/// that fails and leaves the entries after it encrypted. So the strings are read
/// from the object's bytes in the file and decrypted here.
fn decrypt_text_entries(
    doc: &Document,
    pdf: &[u8],
    id: ObjectId,
    signature: &Dictionary,
) -> Dictionary {
    let mut out = signature.clone();
    let Some(state) = doc.encryption_state.as_ref() else {
        return out;
    };
    let Some(XrefEntry::Normal { offset, .. }) = doc.reference_table.get(id.0) else {
        return out;
    };
    let Some(object) = pdf.get(*offset as usize..) else {
        return out;
    };
    for (key, raw) in raw_strings(object) {
        let mut value = Object::String(raw, lopdf::StringFormat::Literal);
        if key != b"Contents" && lopdf::encryption::decrypt_object(state, id, &mut value).is_ok() {
            out.set(key, value);
        }
    }
    out
}

/// String values of the top level entries of the dictionary that starts the
/// indirect object at the beginning of `object` (`N G obj << ... >>`).
fn raw_strings(object: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Some(start) = object.windows(2).position(|w| w == b"<<") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut i = start + 2;
    let mut depth = 0usize; // nesting of dictionaries and arrays inside the top one
    let mut key: Option<Vec<u8>> = None;
    while i < object.len() {
        match object[i] {
            b'%' => {
                while i < object.len() && !matches!(object[i], b'\r' | b'\n') {
                    i += 1;
                }
            }
            b'/' => {
                let end = object[i + 1..]
                    .iter()
                    .position(|b| b.is_ascii_whitespace() || b"/<>[]()%{}".contains(b))
                    .map_or(object.len(), |p| i + 1 + p);
                if depth == 0 {
                    key = match key {
                        // A name value, not a key.
                        Some(_) => None,
                        None => Some(object[i + 1..end].to_vec()),
                    };
                }
                i = end;
                continue;
            }
            b'<' if object.get(i + 1) == Some(&b'<') => {
                depth += 1;
                key = None;
                i += 2;
                continue;
            }
            b'>' if object.get(i + 1) == Some(&b'>') => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
                i += 2;
                continue;
            }
            b'[' => {
                if depth == 0 {
                    key = None;
                }
                depth += 1;
            }
            b']' => depth = depth.saturating_sub(1),
            b'<' => {
                let end = object[i..]
                    .iter()
                    .position(|&b| b == b'>')
                    .map_or(object.len(), |p| i + p);
                if let (0, Some(name)) = (depth, key.take())
                    && let Some(bytes) = decode_hex(&object[i + 1..end])
                {
                    out.push((name, bytes));
                }
                i = end + 1;
                continue;
            }
            b'(' => {
                let (bytes, end) = literal_string(object, i);
                if let (0, Some(name)) = (depth, key.take()) {
                    out.push((name, bytes));
                }
                i = end;
                continue;
            }
            b if b.is_ascii_whitespace() => {}
            _ => {
                if depth == 0 {
                    key = None;
                }
            }
        }
        i += 1;
    }
    out
}

/// Decodes the literal string starting at `object[start]` (`(`); returns its
/// bytes and the offset after the closing `)`.
fn literal_string(object: &[u8], start: usize) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut i = start + 1;
    while i < object.len() {
        match object[i] {
            b'\\' => {
                i += 1;
                match object.get(i) {
                    Some(b'n') => out.push(b'\n'),
                    Some(b'r') => out.push(b'\r'),
                    Some(b't') => out.push(b'\t'),
                    Some(b'b') => out.push(8),
                    Some(b'f') => out.push(12),
                    Some(b'\r') => {
                        if object.get(i + 1) == Some(&b'\n') {
                            i += 1;
                        }
                    }
                    Some(b'\n') => {}
                    Some(d @ b'0'..=b'7') => {
                        let mut value = u32::from(d - b'0');
                        for _ in 0..2 {
                            match object.get(i + 1) {
                                Some(d @ b'0'..=b'7') => {
                                    value = value * 8 + u32::from(d - b'0');
                                    i += 1;
                                }
                                _ => break,
                            }
                        }
                        out.push(value as u8);
                    }
                    Some(&other) => out.push(other),
                    None => break,
                }
            }
            b'(' => {
                depth += 1;
                out.push(b'(');
            }
            b')' if depth == 0 => return (out, i + 1),
            b')' => {
                depth -= 1;
                out.push(b')');
            }
            b => out.push(b),
        }
        i += 1;
    }
    (out, i)
}

/// Whether nothing but whitespace follows `end` in `pdf`.
fn covers_rest(pdf: &[u8], end: usize) -> bool {
    pdf[end..]
        .iter()
        .all(|b| b.is_ascii_whitespace() || *b == 0)
}

fn decode_hex(hex: &[u8]) -> Option<Vec<u8>> {
    let digits: Vec<u8> = hex
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|&b| char::from(b).to_digit(16).map(|d| d as u8))
        .collect::<Option<_>>()?;
    // An odd number of digits ends with an implicit 0.
    Some(
        digits
            .chunks(2)
            .map(|pair| pair[0] << 4 | pair.get(1).copied().unwrap_or(0))
            .collect(),
    )
}

/// The first DER TLV of `bytes`, dropping the zero padding of `/Contents`.
pub(super) fn der_prefix(bytes: &[u8]) -> Option<&[u8]> {
    let first = *bytes.get(1)?;
    let (header, len) = if first < 0x80 {
        (2, usize::from(first))
    } else {
        let octets = usize::from(first & 0x7f);
        if octets == 0 || octets > 4 {
            return None;
        }
        let len = bytes
            .get(2..2 + octets)?
            .iter()
            .fold(0usize, |acc, &b| acc << 8 | usize::from(b));
        (2 + octets, len)
    };
    bytes.get(..header.checked_add(len)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_raw_strings() {
        let object = b"8 0 obj\n<</Type /Sig/ByteRange [0 1 2 3]/Contents <0A0b>/Prop_Build <</App <</Name /X>>>>\
            /M (D:2026\\(x\\)\\101\\\n)/Name <414243>/Reason (a (b) c)>>\nendobj";
        let strings = raw_strings(object);
        assert_eq!(
            strings,
            [
                (b"Contents".to_vec(), vec![0x0a, 0x0b]),
                (b"M".to_vec(), b"D:2026(x)A".to_vec()),
                (b"Name".to_vec(), b"ABC".to_vec()),
                (b"Reason".to_vec(), b"a (b) c".to_vec()),
            ]
        );
    }
}
