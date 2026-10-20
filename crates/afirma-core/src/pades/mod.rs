//! PAdES signatures (ETSI EN 319 142, `ETSI.CAdES.detached`), as AutoFirma
//! produces them:
//!
//! * the signature is appended to the PDF as an incremental update, so the
//!   original bytes and any previous signature stay intact;
//! * the CMS signed attributes are `contentType`, `messageDigest`,
//!   `signingCertificateV2` and, for PAdES-EPES, `signaturePolicyIdentifier`.
//!   The signing time goes in the signature dictionary (`/M`);
//! * optional visible signature with AutoFirma's `layer2Text` placeholders and a
//!   rubric image, certification (DocMDP) and password protected documents.
//!
//! Like CAdES, signing has two phases ([`prepare`] and [`PreparedPdf::finish`])
//! so the private key operation can happen elsewhere.

use std::collections::BTreeMap;

use lopdf::{Dictionary, Document, Object, ObjectId, Stream, xref::XrefType};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::{
    algorithm::KeyType,
    cades::{self, AttributeOptions, PreparedSignature},
    cert::name_attribute,
    digest::DigestAlgorithm,
    error::{Error, Result},
    keystore::SigningKey,
    policy::SignaturePolicy,
};

mod appearance;
mod font_metrics;
mod layer_text;
mod pdf;
mod verify;

pub use appearance::{Font, FontColor, FontFamily};
pub use layer_text::TextMask;
pub use verify::{PdfSignatureReport, PdfVerifyReport, verify};

use pdf::{DateTime, text_string, write_dictionary, write_object};

/// Space reserved for the CMS signature beyond its estimated size. Leaves room
/// for signatures whose size varies (ECDSA) and for a future timestamp.
const RESERVED_MARGIN: usize = 2048;

/// DocMDP certification level (AutoFirma's `certificationLevel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CertificationLevel {
    /// Ordinary (approval) signature (`0`).
    #[default]
    NotCertified,
    /// Certified, no changes allowed (`1`).
    NoChanges,
    /// Certified, form filling and signing allowed (`2`).
    FormFilling,
    /// Certified, form filling, signing and annotations allowed (`3`).
    FormFillingAndAnnotations,
}

impl CertificationLevel {
    /// DocMDP `/P` value, `None` when not certified.
    fn permissions(self) -> Option<i64> {
        match self {
            CertificationLevel::NotCertified => None,
            CertificationLevel::NoChanges => Some(1),
            CertificationLevel::FormFilling => Some(2),
            CertificationLevel::FormFillingAndAnnotations => Some(3),
        }
    }

    /// Level from a DocMDP `/P` value.
    pub fn from_permissions(p: i64) -> Self {
        match p {
            1 => CertificationLevel::NoChanges,
            3 => CertificationLevel::FormFillingAndAnnotations,
            _ => CertificationLevel::FormFilling,
        }
    }
}

/// Pages where a visible signature is drawn (AutoFirma's `signaturePages`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignaturePages {
    /// Last page (AutoFirma's default).
    Last,
    /// These pages, 1-based; negative numbers count from the end (`-1` is the last page).
    Pages(Vec<i32>),
    /// Every page.
    All,
    /// A new blank page appended at the end, the size of the first one (`append`).
    Append,
}

/// Rectangle in page coordinates (points, origin at the lower left corner of the
/// page as displayed), as AutoFirma's `signaturePositionOnPage*` parameters.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Rect {
    /// Lower left x.
    pub llx: f32,
    /// Lower left y.
    pub lly: f32,
    /// Upper right x.
    pub urx: f32,
    /// Upper right y.
    pub ury: f32,
}

impl Rect {
    fn width(&self) -> f32 {
        self.urx - self.llx
    }

    fn height(&self) -> f32 {
        self.ury - self.lly
    }
}

/// Visible signature options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisibleSignature {
    /// Pages where the signature is drawn.
    pub pages: SignaturePages,
    /// Position on the page.
    pub rect: Rect,
    /// Text with AutoFirma's placeholders (`layer2Text`). `None` uses AutoFirma's
    /// default text, unless there is an image.
    pub text: Option<String>,
    /// Font of the text.
    pub font: Font,
    /// Rubric image (JPEG or PNG), drawn under the text.
    #[serde(with = "serde_bytes", default)]
    pub image: Option<Vec<u8>>,
    /// Hide identifiers (DNI/NIE) in the certificate fields of the text.
    /// `None` hides them unless the certificate is a pseudonym certificate.
    pub obfuscate: Option<bool>,
    /// Obfuscation mask, AutoFirma's default when `None`.
    pub mask: Option<TextMask>,
}

/// Parameters of a PAdES signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PadesParams {
    /// Digest algorithm (AutoFirma's default is SHA-512).
    pub digest: DigestAlgorithm,
    /// Signature policy, turning the signature into PAdES-EPES.
    pub policy: Option<SignaturePolicy>,
    /// Signing time, seconds since the Unix epoch.
    pub signing_time: i64,
    /// Local time offset from UTC in minutes, for `/M` and the visible text.
    pub utc_offset_minutes: i32,
    /// Reason (`signReason`).
    pub reason: Option<String>,
    /// Location (`signatureProductionCity`).
    pub location: Option<String>,
    /// Signer contact information (`signerContact`).
    pub contact: Option<String>,
    /// Certification level.
    pub certification: CertificationLevel,
    /// Visible signature, `None` for an invisible one.
    pub visible: Option<VisibleSignature>,
    /// Password of an encrypted PDF (user or owner).
    pub password: Option<String>,
    /// Sign even if the PDF is certified without allowing changes
    /// (`allowSigningCertifiedPdfs`); that signature invalidates the certification.
    pub allow_signing_certified: bool,
    /// Bytes reserved for the CMS signature (`signReservedSize`). Estimated when `None`.
    pub reserved_size: Option<usize>,
}

impl PadesParams {
    /// AutoFirma's defaults: invisible PAdES-BES with SHA-512.
    pub fn new(signing_time: i64) -> Self {
        PadesParams {
            digest: DigestAlgorithm::Sha512,
            policy: None,
            signing_time,
            utc_offset_minutes: 0,
            reason: None,
            location: None,
            contact: None,
            certification: CertificationLevel::NotCertified,
            visible: None,
            password: None,
            allow_signing_certified: false,
            reserved_size: None,
        }
    }
}

/// Information about a PDF, to offer the signature options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PdfInfo {
    /// Size of every page as displayed (width, height), in points.
    pub pages: Vec<(f32, f32)>,
    /// The PDF is encrypted.
    pub encrypted: bool,
    /// Number of signature fields that are signed.
    pub signatures: usize,
    /// Certification of the document.
    pub certification: CertificationLevel,
}

/// Loads a PDF, decrypting it if needed.
fn load(pdf: &[u8], password: Option<&str>) -> Result<Document> {
    if pdf.is_empty() {
        return Err(Error::EmptyData);
    }
    let result = match password {
        Some(password) => {
            Document::load_mem_with_options(pdf, lopdf::LoadOptions::with_password(password))
        }
        None => Document::load_mem(pdf),
    };
    let doc = result.map_err(|e| match e {
        lopdf::Error::InvalidPassword | lopdf::Error::Decryption(_) => match password {
            Some(_) => Error::WrongPdfPassword,
            None => Error::PdfPasswordRequired,
        },
        other => Error::InvalidPdf(other.to_string()),
    })?;
    // Encrypted documents that still need a password are reported as encrypted.
    if doc.is_encrypted() {
        return Err(match password {
            Some(_) => Error::WrongPdfPassword,
            None => Error::PdfPasswordRequired,
        });
    }
    Ok(doc)
}

/// Whether `pdf` has signatures. Encrypted PDFs, which cannot be read without
/// their password, are reported unsigned.
pub fn is_signed(pdf: &[u8]) -> bool {
    info(pdf, None).is_ok_and(|info| info.signatures > 0)
}

/// Reads the pages, encryption and signatures of a PDF.
pub fn info(pdf: &[u8], password: Option<&str>) -> Result<PdfInfo> {
    let doc = load(pdf, password)?;
    let pages = doc
        .get_pages()
        .values()
        .map(|&id| {
            let page = Page::read(&doc, id)?;
            Ok(page.displayed_size())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PdfInfo {
        pages,
        encrypted: doc.encryption_state.is_some(),
        signatures: signature_fields(&doc)
            .iter()
            .filter(|field| field.signed)
            .count(),
        certification: certification(&doc),
    })
}

/// Follows references until a direct object.
fn resolve<'a>(doc: &'a Document, mut object: &'a Object) -> &'a Object {
    for _ in 0..32 {
        match object {
            Object::Reference(id) => match doc.get_object(*id) {
                Ok(target) => object = target,
                Err(_) => return &Object::Null,
            },
            _ => return object,
        }
    }
    &Object::Null
}

fn dict_get<'a>(doc: &'a Document, dict: &'a Dictionary, key: &[u8]) -> Option<&'a Object> {
    dict.get(key).ok().map(|object| resolve(doc, object))
}

fn number(object: &Object) -> Option<f32> {
    match object {
        Object::Integer(i) => Some(*i as f32),
        Object::Real(r) => Some(*r),
        _ => None,
    }
}

/// Page geometry.
#[derive(Debug, Clone, Copy)]
struct Page {
    id: ObjectId,
    /// MediaBox (llx, lly, urx, ury).
    media_box: [f32; 4],
    /// `/Rotate`, in degrees clockwise.
    rotation: i64,
}

impl Page {
    fn read(doc: &Document, id: ObjectId) -> Result<Self> {
        let invalid = || Error::InvalidPdf(format!("página {} {} no válida", id.0, id.1));
        // MediaBox and Rotate are inheritable from the page tree.
        let mut media_box = None;
        let mut rotation = None;
        let mut node = doc.get_dictionary(id).map_err(|_| invalid())?;
        for _ in 0..64 {
            if media_box.is_none() {
                media_box = dict_get(doc, node, b"MediaBox")
                    .and_then(|o| o.as_array().ok())
                    .and_then(|a| {
                        let values: Vec<f32> =
                            a.iter().filter_map(|o| number(resolve(doc, o))).collect();
                        <[f32; 4]>::try_from(values).ok()
                    });
            }
            if rotation.is_none() {
                rotation = dict_get(doc, node, b"Rotate").and_then(|o| o.as_i64().ok());
            }
            match dict_get(doc, node, b"Parent").and_then(|o| o.as_dict().ok()) {
                Some(parent) => node = parent,
                None => break,
            }
        }
        let [x0, y0, x1, y1] = media_box.unwrap_or([0.0, 0.0, 612.0, 792.0]);
        Ok(Page {
            id,
            media_box: [x0.min(x1), y0.min(y1), x0.max(x1), y0.max(y1)],
            rotation: rotation.unwrap_or(0).rem_euclid(360),
        })
    }

    fn size(&self) -> (f32, f32) {
        (
            self.media_box[2] - self.media_box[0],
            self.media_box[3] - self.media_box[1],
        )
    }

    /// Width and height as displayed, after `/Rotate`.
    fn displayed_size(&self) -> (f32, f32) {
        let (w, h) = self.size();
        if self.rotation % 180 == 90 {
            (h, w)
        } else {
            (w, h)
        }
    }

    /// Converts a rectangle in displayed coordinates to default user space.
    fn user_space_rect(&self, rect: &Rect) -> [f32; 4] {
        let (w, h) = self.size();
        let point = |x: f32, y: f32| match self.rotation {
            90 => (w - y, x),
            180 => (w - x, h - y),
            270 => (y, h - x),
            _ => (x, y),
        };
        let (ax, ay) = point(rect.llx, rect.lly);
        let (bx, by) = point(rect.urx, rect.ury);
        let [ox, oy, ..] = self.media_box;
        [
            ax.min(bx) + ox,
            ay.min(by) + oy,
            ax.max(bx) + ox,
            ay.max(by) + oy,
        ]
    }
}

/// A signature field found in the document.
#[derive(Debug)]
struct SignatureField {
    name: String,
    signed: bool,
}

/// Every terminal field of the AcroForm with its fully qualified name.
fn form_fields(doc: &Document) -> Vec<(String, &Dictionary)> {
    fn walk<'a>(
        doc: &'a Document,
        fields: &[&'a Object],
        prefix: &str,
        out: &mut Vec<(String, &'a Dictionary)>,
        depth: usize,
    ) {
        if depth > 32 {
            return;
        }
        for field in fields {
            let Ok(dict) = resolve(doc, field).as_dict() else {
                continue;
            };
            let partial = dict_get(doc, dict, b"T")
                .and_then(|t| t.as_str().ok())
                .map(pdf::decode_text_string);
            let name = match (prefix.is_empty(), partial) {
                (_, None) => prefix.to_string(),
                (true, Some(partial)) => partial,
                (false, Some(partial)) => format!("{prefix}.{partial}"),
            };
            // Kids with names are fields; without names they are widgets.
            let kids: Vec<&Object> = dict_get(doc, dict, b"Kids")
                .and_then(|k| k.as_array().ok())
                .map(|k| k.iter().collect())
                .unwrap_or_default();
            let field_kids: Vec<&Object> = kids
                .into_iter()
                .filter(|kid| resolve(doc, kid).as_dict().is_ok_and(|kid| kid.has(b"T")))
                .collect();
            if field_kids.is_empty() {
                out.push((name, dict));
            } else {
                walk(doc, &field_kids, &name, out, depth + 1);
            }
        }
    }

    let mut out = Vec::new();
    let fields = doc
        .catalog()
        .ok()
        .and_then(|catalog| dict_get(doc, catalog, b"AcroForm"))
        .and_then(|form| form.as_dict().ok())
        .and_then(|form| dict_get(doc, form, b"Fields"))
        .and_then(|fields| fields.as_array().ok());
    if let Some(fields) = fields {
        let fields: Vec<&Object> = fields.iter().collect();
        walk(doc, &fields, "", &mut out, 0);
    }
    out
}

fn signature_fields(doc: &Document) -> Vec<SignatureField> {
    form_fields(doc)
        .into_iter()
        .filter(|(_, dict)| {
            dict_get(doc, dict, b"FT").and_then(|ft| ft.as_name().ok()) == Some(b"Sig")
        })
        .map(|(name, dict)| SignatureField {
            name,
            signed: dict_get(doc, dict, b"V").is_some_and(|v| v.as_dict().is_ok()),
        })
        .collect()
}

/// Certification level of the document, from the catalog's `/Perms /DocMDP`.
fn certification(doc: &Document) -> CertificationLevel {
    let p = (|| {
        let catalog = doc.catalog().ok()?;
        let perms = dict_get(doc, catalog, b"Perms")?.as_dict().ok()?;
        let signature = dict_get(doc, perms, b"DocMDP")?.as_dict().ok()?;
        let references = dict_get(doc, signature, b"Reference")?.as_array().ok()?;
        references.iter().find_map(|reference| {
            let reference = resolve(doc, reference).as_dict().ok()?;
            if dict_get(doc, reference, b"TransformMethod")?
                .as_name()
                .ok()?
                != b"DocMDP"
            {
                return None;
            }
            // P defaults to 2.
            Some(
                dict_get(doc, reference, b"TransformParams")
                    .and_then(|params| params.as_dict().ok())
                    .and_then(|params| dict_get(doc, params, b"P"))
                    .and_then(|p| p.as_i64().ok())
                    .unwrap_or(2),
            )
        })
    })();
    p.map_or(
        CertificationLevel::NotCertified,
        CertificationLevel::from_permissions,
    )
}

/// An object of the incremental update.
#[derive(Debug)]
enum Body {
    Object(Object),
    /// The signature dictionary, already serialized.
    Signature(SignatureDictionary),
}

/// Serialized signature dictionary with the offsets of its placeholders.
#[derive(Debug)]
struct SignatureDictionary {
    bytes: Vec<u8>,
    /// Offset of the `ByteRange` array (`[`).
    byte_range: usize,
    /// Offset of the `Contents` hex string (`<`).
    contents: usize,
}

/// Width of each number of the `ByteRange` placeholder.
const BYTE_RANGE_DIGITS: usize = 10;

impl SignatureDictionary {
    /// Dictionary of a signature (`/Sig`, `ETSI.CAdES.detached`).
    fn new(entries: &Dictionary, contents_len: usize) -> Self {
        Self::with_header(
            b"<</Type /Sig/Filter /Adobe.PPKLite/SubFilter /ETSI.CAdES.detached",
            entries,
            contents_len,
        )
    }

    /// Dictionary of a document timestamp (`/DocTimeStamp`, `ETSI.RFC3161`).
    fn document_timestamp(contents_len: usize) -> Self {
        Self::with_header(
            b"<</Type /DocTimeStamp/Filter /Adobe.PPKLite/SubFilter /ETSI.RFC3161",
            &Dictionary::new(),
            contents_len,
        )
    }

    fn with_header(header: &[u8], entries: &Dictionary, contents_len: usize) -> Self {
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(b"/ByteRange ");
        let byte_range = bytes.len();
        let zero = "0".repeat(BYTE_RANGE_DIGITS);
        bytes.extend_from_slice(format!("[0 {zero} {zero} {zero}]").as_bytes());
        bytes.extend_from_slice(b"/Contents ");
        let contents = bytes.len();
        bytes.push(b'<');
        bytes.extend(std::iter::repeat_n(b'0', contents_len * 2));
        bytes.push(b'>');
        // The rest of the entries, without the enclosing << >>.
        let mut rest = Vec::new();
        write_dictionary(&mut rest, entries);
        bytes.extend_from_slice(&rest[2..]);
        SignatureDictionary {
            bytes,
            byte_range,
            contents,
        }
    }
}

/// Objects added or changed by the signature.
struct Update<'a> {
    doc: &'a Document,
    objects: BTreeMap<ObjectId, Body>,
    next_id: u32,
}

impl<'a> Update<'a> {
    fn new(doc: &'a Document) -> Self {
        let size = doc
            .trailer
            .get(b"Size")
            .ok()
            .and_then(|s| s.as_i64().ok())
            .unwrap_or(0);
        let next_id = u32::try_from(size).unwrap_or(0).max(doc.max_id + 1);
        Update {
            doc,
            objects: BTreeMap::new(),
            next_id,
        }
    }

    fn add(&mut self, object: impl Into<Object>) -> ObjectId {
        let id = (self.next_id, 0);
        self.next_id += 1;
        self.objects.insert(id, Body::Object(object.into()));
        id
    }

    /// The current version of an object: changed in this update, or as in the document.
    fn get(&self, id: ObjectId) -> Result<&Object> {
        match self.objects.get(&id) {
            Some(Body::Object(object)) => Ok(object),
            Some(Body::Signature(_)) => Err(Error::InvalidPdf("objeto de firma".to_string())),
            None => self
                .doc
                .get_object(id)
                .map_err(|e| Error::InvalidPdf(e.to_string())),
        }
    }

    /// A copy of an object of the document to change in this update.
    fn get_mut(&mut self, id: ObjectId) -> Result<&mut Object> {
        if !self.objects.contains_key(&id) {
            let object = self.get(id)?.clone();
            self.objects.insert(id, Body::Object(object));
        }
        match self.objects.get_mut(&id) {
            Some(Body::Object(object)) => Ok(object),
            _ => Err(Error::InvalidPdf("objeto de firma".to_string())),
        }
    }

    fn dict_mut(&mut self, id: ObjectId) -> Result<&mut Dictionary> {
        self.get_mut(id)?
            .as_dict_mut()
            .map_err(|_| Error::InvalidPdf(format!("el objeto {} no es un diccionario", id.0)))
    }

    /// Makes `dict[key]` an indirect dictionary (creating it if missing) and
    /// returns its id, so it can be changed on its own.
    fn indirect_dict(&mut self, holder: ObjectId, key: &[u8]) -> Result<ObjectId> {
        let current = self
            .get(holder)?
            .as_dict()
            .ok()
            .and_then(|d| d.get(key).ok())
            .cloned();
        match current {
            Some(Object::Reference(id)) if self.get(id)?.as_dict().is_ok() => Ok(id),
            Some(Object::Dictionary(dict)) => {
                let id = self.add(dict);
                self.dict_mut(holder)?.set(key, id);
                Ok(id)
            }
            _ => {
                let id = self.add(Dictionary::new());
                self.dict_mut(holder)?.set(key, id);
                Ok(id)
            }
        }
    }

    /// Appends `value` to the array `dict[key]`, direct or indirect, creating it if missing.
    fn push(&mut self, holder: ObjectId, key: &[u8], value: Object) -> Result<()> {
        let current = self
            .get(holder)?
            .as_dict()
            .ok()
            .and_then(|d| d.get(key).ok())
            .cloned();
        match current {
            Some(Object::Reference(id)) if self.get(id)?.as_array().is_ok() => {
                if let Object::Array(array) = self.get_mut(id)? {
                    array.push(value);
                }
            }
            Some(Object::Array(mut array)) => {
                array.push(value);
                self.dict_mut(holder)?.set(key, array);
            }
            _ => self.dict_mut(holder)?.set(key, vec![value]),
        }
        Ok(())
    }

    /// Serializes the update after `original`, with its cross-reference section.
    /// Returns the whole document and the offset of the signature dictionary.
    fn write(self, original: &[u8]) -> Result<(Vec<u8>, usize)> {
        let doc = self.doc;
        let mut out = Vec::with_capacity(original.len() + 64 * 1024);
        out.extend_from_slice(original);
        if !matches!(out.last(), Some(b'\n' | b'\r')) {
            out.push(b'\n');
        }

        let encryption = doc.encryption_state.as_ref();
        let mut offsets = BTreeMap::new();
        let mut signature_offset = 0;
        for (id, body) in self.objects {
            offsets.insert(id, out.len());
            out.extend_from_slice(format!("{} {} obj\n", id.0, id.1).as_bytes());
            match body {
                Body::Object(mut object) => {
                    if let Some(state) = encryption {
                        lopdf::encryption::encrypt_object(state, id, &mut object)
                            .map_err(|e| Error::InvalidPdf(e.to_string()))?;
                    }
                    write_object(&mut out, &object);
                }
                Body::Signature(signature) => {
                    signature_offset = out.len();
                    out.extend_from_slice(&signature.bytes);
                }
            }
            out.extend_from_slice(b"\nendobj\n");
        }

        // Trailer entries carried over from the previous one.
        let mut trailer = Dictionary::new();
        for key in [&b"Root"[..], b"Info", b"ID"] {
            if let Ok(value) = doc.trailer.get(key) {
                trailer.set(key, value.clone());
            }
        }
        if let Some(id) = encryption.and_then(|state| state.encrypt_object_id()) {
            trailer.set("Encrypt", id);
        }
        trailer.set("Prev", doc.xref_start as i64);

        let xref_offset = out.len();
        match doc.reference_table.cross_reference_type {
            XrefType::CrossReferenceTable => {
                trailer.set("Size", i64::from(self.next_id));
                out.extend_from_slice(b"xref\n");
                for (start, ids) in subsections(offsets.keys().map(|id| id.0)) {
                    out.extend_from_slice(format!("{start} {}\n", ids.len()).as_bytes());
                    for id in ids {
                        let (&(_, generation), &offset) = offsets
                            .range((id, 0)..=(id, u16::MAX))
                            .next()
                            .expect("id comes from offsets");
                        out.extend_from_slice(
                            format!("{offset:010} {generation:05} n\r\n").as_bytes(),
                        );
                    }
                }
                out.extend_from_slice(b"trailer\n");
                write_dictionary(&mut out, &trailer);
                out.push(b'\n');
            }
            XrefType::CrossReferenceStream => {
                // The cross-reference stream is an object of its own section.
                let xref_id = self.next_id;
                offsets.insert((xref_id, 0), xref_offset);
                trailer.set("Size", i64::from(xref_id + 1));
                trailer.set("Type", Object::Name(b"XRef".to_vec()));
                trailer.set("W", vec![1.into(), 4.into(), 2.into()]);
                let mut index = Vec::new();
                let mut rows = Vec::new();
                for (start, ids) in subsections(offsets.keys().map(|id| id.0)) {
                    index.push(Object::Integer(i64::from(start)));
                    index.push(Object::Integer(ids.len() as i64));
                    for id in ids {
                        let (&(_, generation), &offset) = offsets
                            .range((id, 0)..=(id, u16::MAX))
                            .next()
                            .expect("id comes from offsets");
                        rows.push(1);
                        rows.extend_from_slice(
                            &u32::try_from(offset)
                                .map_err(|_| {
                                    Error::InvalidPdf("el PDF es demasiado grande".to_string())
                                })?
                                .to_be_bytes(),
                        );
                        rows.extend_from_slice(&generation.to_be_bytes());
                    }
                }
                trailer.set("Index", index);
                out.extend_from_slice(format!("{xref_id} 0 obj\n").as_bytes());
                write_object(&mut out, &Object::Stream(Stream::new(trailer, rows)));
                out.extend_from_slice(b"\nendobj\n");
            }
        }
        out.extend_from_slice(format!("startxref\n{xref_offset}\n%%EOF\n").as_bytes());
        Ok((out, signature_offset))
    }
}

/// Groups sorted object numbers into runs of consecutive numbers.
fn subsections(ids: impl Iterator<Item = u32>) -> Vec<(u32, Vec<u32>)> {
    let mut sections: Vec<(u32, Vec<u32>)> = Vec::new();
    for id in ids {
        match sections.last_mut() {
            Some((start, run)) if *start + run.len() as u32 == id => run.push(id),
            _ => sections.push((id, vec![id])),
        }
    }
    sections
}

fn name(value: &str) -> Object {
    Object::Name(value.as_bytes().to_vec())
}

fn rect_object(rect: [f32; 4]) -> Object {
    Object::Array(rect.iter().map(|&v| Object::Real(v)).collect())
}

/// A PDF whose signature dictionary is ready and whose CMS signed attributes
/// wait for the private key operation.
#[derive(Debug)]
pub struct PreparedPdf {
    pdf: Vec<u8>,
    /// Offset of the `<` of `/Contents`.
    contents_start: usize,
    /// Offset after the `>` of `/Contents`.
    contents_end: usize,
    cms: PreparedSignature,
}

impl PreparedPdf {
    /// Bytes the private key must sign (the DER CMS signed attributes).
    pub fn to_be_signed(&self) -> &[u8] {
        self.cms.to_be_signed()
    }

    /// Inserts the CMS signature built from the raw `signature` value and
    /// returns the signed PDF.
    pub fn finish(mut self, signature: &[u8]) -> Result<Vec<u8>> {
        let cms = self.cms.finish(signature)?;
        let reserved = (self.contents_end - self.contents_start - 2) / 2;
        if cms.len() > reserved {
            return Err(Error::SignatureTooLarge {
                needed: cms.len(),
                reserved,
            });
        }
        let hex = crate::digest::to_hex(&cms);
        self.pdf[self.contents_start + 1..self.contents_start + 1 + hex.len()]
            .copy_from_slice(hex.as_bytes());
        Ok(self.pdf)
    }
}

/// Signs `pdf` with `key`, producing a PAdES-BES (or EPES, with a policy) signature.
pub fn sign(pdf: &[u8], key: &dyn SigningKey, params: &PadesParams) -> Result<Vec<u8>> {
    let prepared = prepare(pdf, key.certificate_chain(), key.key_type(), params)?;
    let signature = key.sign_raw(params.digest, prepared.to_be_signed())?;
    prepared.finish(&signature)
}

/// First phase of a PAdES signature: appends the signature field and
/// dictionary to `pdf` and builds the CMS signed attributes.
///
/// `chain` is the signer's certificate chain, leaf first.
pub fn prepare(
    pdf: &[u8],
    chain: &[Certificate],
    key_type: KeyType,
    params: &PadesParams,
) -> Result<PreparedPdf> {
    let doc = load(pdf, params.password.as_deref())?;
    let leaf = chain
        .first()
        .ok_or_else(|| Error::Certificate("falta el certificado del firmante".to_string()))?;

    let existing = signature_fields(&doc);
    let level = certification(&doc);
    if level == CertificationLevel::NoChanges && !params.allow_signing_certified {
        return Err(Error::PdfCertified);
    }
    if params.certification != CertificationLevel::NotCertified && existing.iter().any(|f| f.signed)
    {
        return Err(Error::Unsupported(
            "solo la primera firma de un PDF puede certificarlo".to_string(),
        ));
    }

    // Space for the CMS: its size with the largest possible signature value.
    let options = AttributeOptions {
        policy: params.policy.as_ref(),
        ..AttributeOptions::default()
    };
    let estimate = cades::prepare_digest(
        &params.digest.digest(b""),
        None,
        chain,
        key_type,
        params.digest,
        options,
    )?
    .max_encoded_len()?;
    let reserved = params
        .reserved_size
        .unwrap_or(0)
        .max(estimate + RESERVED_MARGIN);

    let mut update = Update::new(&doc);
    let catalog_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|_| Error::InvalidPdf("falta el catálogo".to_string()))?;
    let mut pages: Vec<Page> = doc
        .get_pages()
        .values()
        .map(|&id| Page::read(&doc, id))
        .collect::<Result<_>>()?;
    if pages.is_empty() {
        return Err(Error::InvalidPdf(
            "el documento no tiene páginas".to_string(),
        ));
    }

    // Signature dictionary.
    let date = DateTime::from_unix(params.signing_time, params.utc_offset_minutes);
    let mut entries = Dictionary::new();
    entries.set("M", text_string(&date.to_pdf()));
    if let Some(cn) = name_attribute(
        leaf.tbs_certificate().subject(),
        crate::algorithm::oid::COMMON_NAME,
    ) {
        entries.set("Name", text_string(&cn));
    }
    for (key, value) in [
        ("Reason", &params.reason),
        ("Location", &params.location),
        ("ContactInfo", &params.contact),
    ] {
        if let Some(value) = value.as_deref().filter(|v| !v.is_empty()) {
            entries.set(key, text_string(value));
        }
    }
    if let Some(p) = params.certification.permissions() {
        let mut transform = Dictionary::new();
        transform.set("Type", name("TransformParams"));
        transform.set("P", p);
        transform.set("V", name("1.2"));
        let mut reference = Dictionary::new();
        reference.set("Type", name("SigRef"));
        reference.set("TransformMethod", name("DocMDP"));
        reference.set("TransformParams", transform);
        entries.set("Reference", vec![Object::Dictionary(reference)]);
    }
    let signature_id = (update.next_id, 0);
    update.next_id += 1;
    if let Some(state) = doc.encryption_state.as_ref() {
        // Every string but /Contents is encrypted.
        let mut object = Object::Dictionary(entries);
        lopdf::encryption::encrypt_object(state, signature_id, &mut object)
            .map_err(|e| Error::InvalidPdf(e.to_string()))?;
        entries = object.as_dict().cloned().unwrap_or_default();
    }
    let signature_dict = SignatureDictionary::new(&entries, reserved);
    let (byte_range_offset, contents_offset) = (signature_dict.byte_range, signature_dict.contents);
    update
        .objects
        .insert(signature_id, Body::Signature(signature_dict));

    // Signature field.
    let field_name = (1..)
        .map(|n| format!("Signature{n}"))
        .find(|candidate| existing.iter().all(|f| &f.name != candidate))
        .expect("infinite candidates");
    let mut field = Dictionary::new();
    field.set("FT", name("Sig"));
    field.set("T", text_string(&field_name));
    field.set("V", signature_id);

    // Widgets: one per page with a visible signature; an empty one on the first
    // page for invisible signatures.
    let mut placements: Vec<(Page, [f32; 4])> = Vec::new();
    let mut appearance_text = None;
    if let Some(visible) = &params.visible {
        if visible.rect.width() <= 0.0 || visible.rect.height() <= 0.0 {
            return Err(Error::InvalidSignaturePosition(
                "el área está vacía".to_string(),
            ));
        }
        let selected = select_pages(&mut update, &mut pages, &visible.pages)?;
        for page in selected {
            let (w, h) = page.displayed_size();
            if visible.rect.llx >= w || visible.rect.lly >= h {
                continue;
            }
            // Clip to the page, as AutoFirma does.
            let rect = Rect {
                urx: visible.rect.urx.min(w),
                ury: visible.rect.ury.min(h),
                ..visible.rect
            };
            placements.push((page, page.user_space_rect(&rect)));
        }
        if placements.is_empty() {
            return Err(Error::InvalidSignaturePosition(
                "el área queda fuera de las páginas seleccionadas".to_string(),
            ));
        }
        let template = match &visible.text {
            Some(text) => Some(text.clone()),
            None if visible.image.is_none() => Some(layer_text::default_template(
                params.reason.is_some(),
                params.location.is_some(),
            )),
            None => None,
        };
        let mask = visible.mask.clone().unwrap_or_default();
        let obfuscate = visible
            .obfuscate
            .unwrap_or_else(|| !layer_text::is_pseudonym(leaf));
        appearance_text = template.map(|template| {
            layer_text::expand(
                &template,
                &layer_text::LayerTextContext {
                    certificate: leaf,
                    signing_time: params.signing_time,
                    utc_offset_minutes: params.utc_offset_minutes,
                    reason: params.reason.as_deref(),
                    location: params.location.as_deref(),
                    contact: params.contact.as_deref(),
                    mask: obfuscate.then_some(&mask),
                },
            )
        });
    } else {
        placements.push((pages[0], [0.0; 4]));
    }

    let visible = params.visible.as_ref();
    let image = visible
        .and_then(|v| v.image.as_deref())
        .map(appearance::Image::decode)
        .transpose()?;
    let image_ids = image.map(|image| {
        let size = (image.width, image.height);
        let mut stream = image.stream;
        if let Some(alpha) = image.alpha {
            let alpha_id = update.add(alpha);
            stream.dict.set("SMask", alpha_id);
        }
        (update.add(stream), size)
    });
    let font_id = appearance_text
        .as_ref()
        .map(|_| update.add(visible.map(|v| v.font).unwrap_or_default().dictionary()));

    let widgets: Vec<Dictionary> = placements
        .iter()
        .map(|(page, rect)| {
            let (width, height) = if page.rotation % 180 == 90 {
                (rect[3] - rect[1], rect[2] - rect[0])
            } else {
                (rect[2] - rect[0], rect[3] - rect[1])
            };
            let content = match (visible, &appearance_text) {
                (Some(visible), text) => appearance::content(
                    text.as_deref().unwrap_or(""),
                    &visible.font,
                    width,
                    height,
                    image_ids.map(|(_, size)| size),
                ),
                (None, _) => Vec::new(),
            };
            let mut resources = Dictionary::new();
            if let Some(font_id) = font_id {
                let mut fonts = Dictionary::new();
                fonts.set("F1", font_id);
                resources.set("Font", fonts);
            }
            if let Some((image_id, _)) = image_ids {
                let mut xobjects = Dictionary::new();
                xobjects.set("Img", image_id);
                resources.set("XObject", xobjects);
            }
            let mut form = Dictionary::new();
            form.set("Type", name("XObject"));
            form.set("Subtype", name("Form"));
            form.set("BBox", rect_object([0.0, 0.0, width, height]));
            form.set("Resources", resources);
            if let Some(matrix) = appearance::rotation_matrix(page.rotation) {
                form.set(
                    "Matrix",
                    matrix.iter().map(|&v| Object::Real(v)).collect::<Vec<_>>(),
                );
            }
            let form_id = update.add(Stream::new(form, content));

            let mut widget = Dictionary::new();
            widget.set("Type", name("Annot"));
            widget.set("Subtype", name("Widget"));
            // Print and Locked.
            widget.set("F", 132);
            widget.set("P", page.id);
            widget.set("Rect", rect_object(*rect));
            let mut ap = Dictionary::new();
            ap.set("N", form_id);
            widget.set("AP", ap);
            widget
        })
        .collect();

    let field_id = if let [widget] = widgets.as_slice() {
        // Field and widget merged in one dictionary.
        let mut merged = field;
        for (key, value) in widget.iter() {
            merged.set(key.clone(), value.clone());
        }
        let id = update.add(merged);
        update.push(placements[0].0.id, b"Annots", id.into())?;
        id
    } else {
        let field_id = (update.next_id, 0);
        update.next_id += 1;
        let mut kids = Vec::new();
        for ((page, _), mut widget) in placements.iter().zip(widgets) {
            widget.set("Parent", field_id);
            let id = update.add(widget);
            update.push(page.id, b"Annots", id.into())?;
            kids.push(Object::from(id));
        }
        field.set("Kids", kids);
        update.objects.insert(field_id, Body::Object(field.into()));
        field_id
    };

    // AcroForm: the new field and SigFlags = SignaturesExist | AppendOnly.
    let form_id = update.indirect_dict(catalog_id, b"AcroForm")?;
    update.push(form_id, b"Fields", field_id.into())?;
    update.dict_mut(form_id)?.set("SigFlags", 3);

    if params.certification.permissions().is_some() {
        let mut perms = Dictionary::new();
        perms.set("DocMDP", signature_id);
        update.dict_mut(catalog_id)?.set("Perms", perms);
    }

    let (output, contents_start, contents_end) =
        write_with_byte_range(update, pdf, byte_range_offset, contents_offset, reserved)?;

    let message_digest = params
        .digest
        .digest_parts(&[&output[..contents_start], &output[contents_end..]]);
    let cms = cades::prepare_digest(
        &message_digest,
        None,
        chain,
        key_type,
        params.digest,
        options,
    )?;

    Ok(PreparedPdf {
        pdf: output,
        contents_start,
        contents_end,
        cms,
    })
}

/// Writes `update` after `pdf` and fills the `/ByteRange` of its signature
/// dictionary, whose placeholders are at `byte_range_offset` and
/// `contents_offset` within it. Returns the document and the `/Contents` gap.
fn write_with_byte_range(
    update: Update<'_>,
    pdf: &[u8],
    byte_range_offset: usize,
    contents_offset: usize,
    reserved: usize,
) -> Result<(Vec<u8>, usize, usize)> {
    let (mut output, signature_offset) = update.write(pdf)?;

    // ByteRange: everything but the /Contents hex string.
    let contents_start = signature_offset + contents_offset;
    let contents_end = contents_start + 2 + 2 * reserved;
    let byte_range = format!(
        "[0 {contents_start} {contents_end} {}",
        output.len() - contents_end
    );
    // Same width as the placeholder: `[0 ` + three numbers and two spaces, then `]`.
    let width = 3 + 3 * BYTE_RANGE_DIGITS + 2;
    if byte_range.len() > width {
        return Err(Error::InvalidPdf("el PDF es demasiado grande".to_string()));
    }
    let byte_range = format!("{byte_range:<width$}]");
    let start = signature_offset + byte_range_offset;
    output[start..start + byte_range.len()].copy_from_slice(byte_range.as_bytes());
    Ok((output, contents_start, contents_end))
}

/// The `/Contents` gap of the last signature added to `pdf` (the one at the
/// highest `ByteRange`), as `(start of <, end after >)`.
fn last_contents_gap(pdf: &[u8]) -> Result<(usize, usize)> {
    let invalid = || Error::InvalidPdf("el PDF no tiene firmas".to_string());
    let mut best: Option<(usize, usize)> = None;
    let mut from = 0;
    while let Some(found) = pdf[from..].windows(10).position(|w| w == b"/ByteRange") {
        let at = from + found + 10;
        from = at;
        let rest = &pdf[at..pdf.len().min(at + 64)];
        let Some(open) = rest.iter().position(|&b| b == b'[') else {
            continue;
        };
        let Some(close) = rest.iter().position(|&b| b == b']') else {
            continue;
        };
        let numbers: Vec<usize> = std::str::from_utf8(&rest[open + 1..close.max(open + 1)])
            .unwrap_or("")
            .split_whitespace()
            .filter_map(|n| n.parse().ok())
            .collect();
        if let [0, start, end, _] = numbers[..]
            && start < end
            && end <= pdf.len()
            && pdf[start] == b'<'
            && pdf[end - 1] == b'>'
            && best.is_none_or(|(s, _)| start > s)
        {
            best = Some((start, end));
        }
    }
    best.ok_or_else(invalid)
}

/// Writes `cms` into the `/Contents` gap `(start, end)`, padded with zeros.
fn fill_contents(pdf: &mut [u8], (start, end): (usize, usize), cms: &[u8]) -> Result<()> {
    let reserved = (end - start - 2) / 2;
    if cms.len() > reserved {
        return Err(Error::SignatureTooLarge {
            needed: cms.len(),
            reserved,
        });
    }
    let mut hex = crate::digest::to_hex(cms).into_bytes();
    hex.resize(reserved * 2, b'0');
    pdf[start + 1..end - 1].copy_from_slice(&hex);
    Ok(())
}

/// The CMS signature in the `/Contents` gap.
fn contents_cms(pdf: &[u8], (start, end): (usize, usize)) -> Result<Vec<u8>> {
    let hex = std::str::from_utf8(&pdf[start + 1..end - 1])
        .map_err(|_| Error::InvalidPdf("/Contents no es hexadecimal".to_string()))?;
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Error::InvalidPdf("/Contents no es hexadecimal".to_string()))?;
    // Drop the zero padding after the DER structure.
    verify::der_prefix(&bytes)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::InvalidPdf("/Contents no contiene una firma CMS".to_string()))
}

/// Digests to timestamp for a signature timestamp (PAdES-T): the signature
/// value of the last signature of `pdf`.
pub fn timestamp_imprints(pdf: &[u8], digest: DigestAlgorithm) -> Result<Vec<Vec<u8>>> {
    cades::timestamp_imprints(&contents_cms(pdf, last_contents_gap(pdf)?)?, digest)
}

/// Adds signature timestamps to the CMS of the last signature of `pdf`. The
/// CMS is replaced in place, so it must fit in the space reserved when signing.
pub fn add_timestamps(
    pdf: &[u8],
    digest: DigestAlgorithm,
    responses: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let gap = last_contents_gap(pdf)?;
    let cms = cades::add_timestamps(&contents_cms(pdf, gap)?, digest, responses)?;
    let mut out = pdf.to_vec();
    fill_contents(&mut out, gap, &cms)?;
    Ok(out)
}

/// Space reserved for a document timestamp token: TSA tokens with their
/// certificate chain are usually 3 to 8 KB.
const DOCUMENT_TIMESTAMP_RESERVED: usize = 16 * 1024;

/// First phase of a document timestamp (PAdES-LTA's `DocTimeStamp`): appends
/// an invisible `ETSI.RFC3161` field to `pdf` and returns the PDF and the
/// digest of its signed bytes, to request the token from the TSA. The token is
/// added with [`add_document_timestamp`].
pub fn prepare_document_timestamp(
    pdf: &[u8],
    password: Option<&str>,
    digest: DigestAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let doc = load(pdf, password)?;
    if certification(&doc) == CertificationLevel::NoChanges {
        return Err(Error::PdfCertified);
    }
    let existing = signature_fields(&doc);
    let mut update = Update::new(&doc);
    let catalog_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|_| Error::InvalidPdf("falta el catálogo".to_string()))?;
    let first_page = *doc
        .get_pages()
        .values()
        .next()
        .ok_or_else(|| Error::InvalidPdf("el documento no tiene páginas".to_string()))?;

    let signature_id = (update.next_id, 0);
    update.next_id += 1;
    let dictionary = SignatureDictionary::document_timestamp(DOCUMENT_TIMESTAMP_RESERVED);
    let (byte_range_offset, contents_offset) = (dictionary.byte_range, dictionary.contents);
    update
        .objects
        .insert(signature_id, Body::Signature(dictionary));

    let field_name = (1..)
        .map(|n| format!("Timestamp{n}"))
        .find(|candidate| existing.iter().all(|f| &f.name != candidate))
        .expect("infinite candidates");
    let mut field = Dictionary::new();
    field.set("FT", name("Sig"));
    field.set("T", text_string(&field_name));
    field.set("V", signature_id);
    field.set("Type", name("Annot"));
    field.set("Subtype", name("Widget"));
    field.set("F", 132);
    field.set("P", first_page);
    field.set("Rect", rect_object([0.0; 4]));
    let field_id = update.add(field);
    update.push(first_page, b"Annots", field_id.into())?;
    let form_id = update.indirect_dict(catalog_id, b"AcroForm")?;
    update.push(form_id, b"Fields", field_id.into())?;
    update.dict_mut(form_id)?.set("SigFlags", 3);

    let (output, contents_start, contents_end) = write_with_byte_range(
        update,
        pdf,
        byte_range_offset,
        contents_offset,
        DOCUMENT_TIMESTAMP_RESERVED,
    )?;
    let imprint = digest.digest_parts(&[&output[..contents_start], &output[contents_end..]]);
    Ok((output, imprint))
}

/// Adds the token of a TSA `response` to a PDF from [`prepare_document_timestamp`].
pub fn add_document_timestamp(
    prepared: &[u8],
    digest: DigestAlgorithm,
    response: &[u8],
) -> Result<Vec<u8>> {
    let (start, end) = last_contents_gap(prepared)?;
    let imprint = digest.digest_parts(&[&prepared[..start], &prepared[end..]]);
    let token = crate::tsp::token_for(response, digest, &imprint)?;
    let mut out = prepared.to_vec();
    fill_contents(&mut out, (start, end), &token)?;
    Ok(out)
}

/// Pages for a visible signature, appending a blank page if requested.
fn select_pages(
    update: &mut Update<'_>,
    pages: &mut Vec<Page>,
    selection: &SignaturePages,
) -> Result<Vec<Page>> {
    let total = pages.len() as i64;
    let selected: Vec<Page> = match selection {
        SignaturePages::Last => vec![pages[pages.len() - 1]],
        SignaturePages::All => pages.clone(),
        SignaturePages::Pages(numbers) => {
            let mut indexes: Vec<i64> = numbers
                .iter()
                .map(|&n| {
                    if n < 0 {
                        total + i64::from(n) + 1
                    } else {
                        i64::from(n)
                    }
                })
                .filter(|n| (1..=total).contains(n))
                .collect();
            indexes.sort_unstable();
            indexes.dedup();
            if indexes.is_empty() {
                // AutoFirma falls back to the last page.
                indexes.push(total);
            }
            indexes.iter().map(|&n| pages[(n - 1) as usize]).collect()
        }
        SignaturePages::Append => {
            let first = pages[0];
            let (w, h) = first.displayed_size();
            let doc = update.doc;
            let root_pages = doc
                .catalog()
                .ok()
                .and_then(|catalog| catalog.get(b"Pages").ok())
                .and_then(|p| p.as_reference().ok())
                .ok_or_else(|| Error::InvalidPdf("falta el árbol de páginas".to_string()))?;
            let mut page = Dictionary::new();
            page.set("Type", name("Page"));
            page.set("Parent", root_pages);
            page.set("MediaBox", rect_object([0.0, 0.0, w, h]));
            page.set("Resources", Dictionary::new());
            let id = update.add(page);
            update.push(root_pages, b"Kids", id.into())?;
            let pages_dict = update.dict_mut(root_pages)?;
            let count = pages_dict
                .get(b"Count")
                .and_then(Object::as_i64)
                .unwrap_or(total);
            pages_dict.set("Count", count + 1);
            let page = Page {
                id,
                media_box: [0.0, 0.0, w, h],
                rotation: 0,
            };
            pages.push(page);
            vec![page]
        }
    };
    Ok(selected)
}

#[cfg(test)]
mod tests;
