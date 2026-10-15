//! Message digests used by the signature formats.

use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Digest algorithms supported by AutoFirma.
///
/// SHA-1 is only kept to verify legacy signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DigestAlgorithm {
    /// SHA-1 (verification of legacy signatures only).
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512, AutoFirma's default.
    Sha512,
}

impl DigestAlgorithm {
    /// Computes the digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
            DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// Name as used by AutoFirma (`SHA-256`, ...).
    pub fn name(self) -> &'static str {
        match self {
            DigestAlgorithm::Sha1 => "SHA-1",
            DigestAlgorithm::Sha256 => "SHA-256",
            DigestAlgorithm::Sha384 => "SHA-384",
            DigestAlgorithm::Sha512 => "SHA-512",
        }
    }
}

/// Lowercase hexadecimal representation of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_abc() {
        assert_eq!(
            to_hex(&DigestAlgorithm::Sha256.digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn digest_lengths() {
        assert_eq!(DigestAlgorithm::Sha1.digest(b"").len(), 20);
        assert_eq!(DigestAlgorithm::Sha384.digest(b"").len(), 48);
        assert_eq!(DigestAlgorithm::Sha512.digest(b"").len(), 64);
    }
}
