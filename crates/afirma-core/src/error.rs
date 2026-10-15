//! Error type shared by every module of the crate.

/// Errors produced by `afirma-core`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input data is empty.
    #[error("los datos están vacíos")]
    EmptyData,
    /// The requested operation is not implemented yet.
    #[error("operación no soportada: {0}")]
    Unsupported(String),
}

/// Result alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
