//! Error type shared by every module of the crate.

/// Errors produced by `afirma-core`. Messages are in Spanish, ready to show to the user.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input data is empty.
    #[error("los datos están vacíos")]
    EmptyData,
    /// The requested operation is not implemented yet.
    #[error("operación no soportada: {0}")]
    Unsupported(String),
    /// Wrong keystore password.
    #[error("la contraseña del almacén no es correcta")]
    WrongPassword,
    /// The PKCS#12 keystore could not be read.
    #[error("no se pudo leer el almacén PKCS#12: {0}")]
    Pkcs12(String),
    /// Invalid private key.
    #[error("clave privada no válida: {0}")]
    Key(String),
    /// Unsupported private key type.
    #[error("tipo de clave no soportado: {0}")]
    UnsupportedKey(String),
    /// Invalid certificate.
    #[error("certificado no válido: {0}")]
    Certificate(String),
    /// No key with the given id.
    #[error("no se encuentra la clave seleccionada")]
    KeyNotFound,
    /// The private key operation failed.
    #[error("error al firmar: {0}")]
    Signing(String),
    /// Invalid certificate filter expression.
    #[error("filtro de certificados no válido: {0}")]
    InvalidFilter(String),
    /// Invalid signature policy.
    #[error("política de firma no válida: {0}")]
    InvalidPolicy(String),
    /// Invalid time.
    #[error("fecha no válida: {0}")]
    InvalidTime(i64),
    /// The data is not a valid signature.
    #[error("la firma no es válida: {0}")]
    InvalidSignature(String),
    /// An explicit signature was verified without the signed data.
    #[error("la firma no contiene los datos firmados; seleccione también el fichero original")]
    MissingSignedData,
    /// The PDF could not be read.
    #[error("el PDF no es válido: {0}")]
    InvalidPdf(String),
    /// The PDF is encrypted and no password was given.
    #[error("el PDF está protegido con contraseña")]
    PdfPasswordRequired,
    /// Wrong PDF password.
    #[error("la contraseña del PDF no es correcta")]
    WrongPdfPassword,
    /// The PDF is certified and does not allow more signatures.
    #[error("el PDF está certificado y no admite más firmas")]
    PdfCertified,
    /// The visible signature does not fit in any of the selected pages.
    #[error("la posición de la firma visible no es válida: {0}")]
    InvalidSignaturePosition(String),
    /// The signature does not fit in the space reserved in the PDF.
    #[error("la firma ocupa {needed} bytes y solo se reservaron {reserved}")]
    SignatureTooLarge {
        /// Size of the signature.
        needed: usize,
        /// Space reserved in the PDF.
        reserved: usize,
    },
    /// Triphase signature protocol error.
    #[error("{0}")]
    Triphase(String),
    /// ASN.1 encoding error.
    #[error("error de codificación ASN.1: {0}")]
    Asn1(#[from] der::Error),
}

/// Result alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
