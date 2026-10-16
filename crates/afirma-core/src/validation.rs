//! Verification of signatures of any supported format, detected from the data.

use serde::{Deserialize, Serialize};

use crate::{
    cades::{self, VerifyReport},
    error::{Error, Result},
    format::DataKind,
    pades::{self, PdfVerifyReport},
};

/// Result of verifying a signature, by format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verification {
    /// CAdES / CMS signature.
    Cades(VerifyReport),
    /// Signatures of a PDF.
    Pades(PdfVerifyReport),
}

impl Verification {
    /// Whether every signature is valid.
    pub fn is_valid(&self) -> bool {
        match self {
            Verification::Cades(report) => report.is_valid(),
            Verification::Pades(report) => report.is_valid(),
        }
    }
}

/// Verifies the integrity of `signature`.
///
/// `data` is the signed data of explicit (detached) CAdES signatures;
/// `pdf_password` opens encrypted PDFs. Certificate trust and revocation are
/// not checked.
pub fn verify(
    signature: &[u8],
    data: Option<&[u8]>,
    pdf_password: Option<&str>,
) -> Result<Verification> {
    if signature.is_empty() {
        return Err(Error::EmptyData);
    }
    match DataKind::detect(signature) {
        DataKind::Pdf => pades::verify(signature, pdf_password).map(Verification::Pades),
        DataKind::CmsSignedData => cades::verify(signature, data).map(Verification::Cades),
        DataKind::Xml => Err(Error::Unsupported(
            "la verificación de firmas XAdES llegará en la fase P3".to_string(),
        )),
        _ => Err(Error::InvalidSignature(
            "el fichero no es una firma CAdES ni un PDF".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(path: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/data/{path}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn detects_the_format() {
        let pdf = verify(&fixture("pades/autofirma-bes-rsa.pdf"), None, None).unwrap();
        assert!(matches!(pdf, Verification::Pades(_)) && pdf.is_valid());

        let cades = verify(
            &fixture("cades/autofirma-explicit-rsa.csig"),
            Some(&fixture("cades/doc.txt")),
            None,
        )
        .unwrap();
        assert!(matches!(cades, Verification::Cades(_)) && cades.is_valid());

        assert!(matches!(
            verify(b"hola", None, None),
            Err(Error::InvalidSignature(_))
        ));
        assert!(matches!(
            verify(&fixture("cades/autofirma-explicit-rsa.csig"), None, None),
            Err(Error::MissingSignedData)
        ));
    }
}
