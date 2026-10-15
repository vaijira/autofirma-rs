//! Detection of the kind of data being signed and the default signature format
//! AutoFirma would choose for it.

use serde::{Deserialize, Serialize};

/// Kind of input data, detected from its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataKind {
    /// PDF document.
    Pdf,
    /// XML document.
    Xml,
    /// OpenDocument (ODF) package.
    Odf,
    /// Office Open XML (OOXML) package.
    Ooxml,
    /// Any other ZIP archive.
    Zip,
    /// CMS / PKCS#7 SignedData structure (an existing CAdES or CMS signature).
    CmsSignedData,
    /// Plain text (valid UTF-8 without control characters).
    Text,
    /// Anything else.
    Binary,
}

/// Signature formats supported by AutoFirma.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureFormat {
    /// CAdES.
    Cades,
    /// PAdES.
    Pades,
    /// XAdES.
    Xades,
    /// FacturaE (XAdES-EPES with the FacturaE policy).
    Facturae,
    /// ODF signature.
    Odf,
    /// OOXML signature.
    Ooxml,
}

impl SignatureFormat {
    /// Name as used by AutoFirma (`CAdES`, `PAdES`, ...).
    pub fn name(self) -> &'static str {
        match self {
            SignatureFormat::Cades => "CAdES",
            SignatureFormat::Pades => "PAdES",
            SignatureFormat::Xades => "XAdES",
            SignatureFormat::Facturae => "FacturaE",
            SignatureFormat::Odf => "ODF",
            SignatureFormat::Ooxml => "OOXML",
        }
    }
}

impl DataKind {
    /// Detects the kind of `data` from its first bytes.
    pub fn detect(data: &[u8]) -> Self {
        if find(head(data, 1024), b"%PDF-").is_some() {
            return DataKind::Pdf;
        }
        if data.starts_with(b"PK\x03\x04") {
            // ODF requires an uncompressed `mimetype` entry as the first file of the package.
            let first_entry = head(data, 128);
            if find(first_entry, b"mimetypeapplication/vnd.oasis.opendocument").is_some() {
                return DataKind::Odf;
            }
            if find(head(data, 64 * 1024), b"[Content_Types].xml").is_some() {
                return DataKind::Ooxml;
            }
            return DataKind::Zip;
        }
        if is_cms_signed_data(data) {
            return DataKind::CmsSignedData;
        }
        if looks_like_xml(data) {
            return DataKind::Xml;
        }
        if looks_like_text(data) {
            return DataKind::Text;
        }
        DataKind::Binary
    }

    /// Signature format AutoFirma uses by default for this kind of data
    /// (PAdES for PDF, XAdES for XML, CAdES otherwise).
    pub fn default_format(self) -> SignatureFormat {
        match self {
            DataKind::Pdf => SignatureFormat::Pades,
            DataKind::Xml => SignatureFormat::Xades,
            _ => SignatureFormat::Cades,
        }
    }

    /// Human readable description, in Spanish.
    pub fn description(self) -> &'static str {
        match self {
            DataKind::Pdf => "Documento PDF",
            DataKind::Xml => "Documento XML",
            DataKind::Odf => "Documento OpenDocument",
            DataKind::Ooxml => "Documento Office (OOXML)",
            DataKind::Zip => "Archivo ZIP",
            DataKind::CmsSignedData => "Firma CMS/CAdES",
            // Same description AutoFirma writes in the CAdES `contentHint` attribute.
            DataKind::Text => "Texto plano",
            DataKind::Binary => "Fichero binario",
        }
    }
}

fn head(data: &[u8], len: usize) -> &[u8] {
    &data[..data.len().min(len)]
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// DER `SEQUENCE` containing the `signedData` content type OID (1.2.840.113549.1.7.2)
/// right after its length.
fn is_cms_signed_data(data: &[u8]) -> bool {
    const SIGNED_DATA_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];

    if data.len() < 2 || data[0] != 0x30 {
        return false;
    }
    let len_octets = match data[1] {
        n if n < 0x80 => 0,
        n => usize::from(n & 0x7f),
    };
    data.get(2 + len_octets..)
        .is_some_and(|rest| rest.starts_with(SIGNED_DATA_OID))
}

fn looks_like_text(data: &[u8]) -> bool {
    let sample = head(data, 8192);
    // Do not reject a sample that ends in the middle of a multi-byte character.
    let valid = match std::str::from_utf8(sample) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none() && e.valid_up_to() + 4 > sample.len(),
    };
    !data.is_empty()
        && valid
        && sample
            .iter()
            .all(|&b| b >= 0x20 || matches!(b, b'\n' | b'\r' | b'\t' | 0x0c))
}

fn looks_like_xml(data: &[u8]) -> bool {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let start = data.iter().position(|b| !b.is_ascii_whitespace());
    start.is_some_and(|i| data[i] == b'<') && find(head(data, 4096), b">").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pdf() {
        assert_eq!(DataKind::detect(b"%PDF-1.7\n..."), DataKind::Pdf);
        assert_eq!(
            DataKind::detect(b"%PDF-1.7").default_format(),
            SignatureFormat::Pades
        );
    }

    #[test]
    fn detects_xml() {
        assert_eq!(
            DataKind::detect(b"\xef\xbb\xbf  <?xml version=\"1.0\"?><a/>"),
            DataKind::Xml
        );
        assert_eq!(
            DataKind::detect(b"<Facturae></Facturae>").default_format(),
            SignatureFormat::Xades
        );
    }

    #[test]
    fn detects_odf() {
        let mut odt = b"PK\x03\x04".to_vec();
        odt.extend_from_slice(&[0; 26]);
        odt.extend_from_slice(b"mimetypeapplication/vnd.oasis.opendocument.text");
        assert_eq!(DataKind::detect(&odt), DataKind::Odf);
    }

    #[test]
    fn detects_ooxml_and_zip() {
        let mut docx = b"PK\x03\x04".to_vec();
        docx.extend_from_slice(&[0; 26]);
        docx.extend_from_slice(b"[Content_Types].xml");
        assert_eq!(DataKind::detect(&docx), DataKind::Ooxml);
        assert_eq!(DataKind::detect(b"PK\x03\x04plain"), DataKind::Zip);
    }

    #[test]
    fn detects_cms_signed_data() {
        let cms = [
            0x30, 0x82, 0x01, 0x00, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07,
            0x02, 0xa0,
        ];
        assert_eq!(DataKind::detect(&cms), DataKind::CmsSignedData);
        assert_eq!(
            DataKind::detect(&cms).default_format(),
            SignatureFormat::Cades
        );
    }

    #[test]
    fn detects_text() {
        assert_eq!(DataKind::detect("Hola, señor\n".as_bytes()), DataKind::Text);
        assert_eq!(
            DataKind::detect(b"hello").default_format(),
            SignatureFormat::Cades
        );
    }

    #[test]
    fn falls_back_to_binary() {
        assert_eq!(DataKind::detect(b"\x00\x01binary"), DataKind::Binary);
        assert_eq!(DataKind::detect(b"\xff\xfe\x00"), DataKind::Binary);
        assert_eq!(DataKind::detect(b""), DataKind::Binary);
    }
}
