//! Signature policies (EPES), with the AGE presets used by AutoFirma.

use base64ct::{Base64, Encoding};
use const_oid::ObjectIdentifier;
use serde::{Deserialize, Serialize};

use crate::{
    digest::DigestAlgorithm,
    error::{Error, Result},
    format::SignatureFormat,
};

/// Signature policy presets, as in AutoFirma's `policy.properties`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyPreset {
    /// Política de firma de la AGE v1.9 (AutoFirma's `FirmaAGE`, the default).
    Age19,
    /// Política de firma de la AGE v1.8.
    Age18,
}

impl PolicyPreset {
    /// Every preset.
    pub const ALL: [PolicyPreset; 2] = [PolicyPreset::Age19, PolicyPreset::Age18];

    /// Human readable name, in Spanish.
    pub fn name(self) -> &'static str {
        match self {
            PolicyPreset::Age19 => "Política de firma de la AGE v1.9",
            PolicyPreset::Age18 => "Política de firma de la AGE v1.8",
        }
    }

    /// Policy for a signature format.
    pub fn policy(self, format: SignatureFormat) -> SignaturePolicy {
        let (identifier, qualifier, hash) = match self {
            PolicyPreset::Age19 => (
                "2.16.724.1.3.1.1.2.1.9",
                "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
                "G7roucf600+f03r/o0bAOQ6WAs0=",
            ),
            PolicyPreset::Age18 => (
                "2.16.724.1.3.1.1.2.1.8",
                "https://sede.administracion.gob.es/PAG_Sede/dam/jcr:b0de3f91-5171-48e2-81f3-5c2407d9c091/politica_firma_AGE_v1_8.pdf",
                match format {
                    SignatureFormat::Xades | SignatureFormat::Facturae => {
                        "V8lVVNGDCPen6VELRD1Ja8HARFk="
                    }
                    _ => "7SxX3erFuH31TvAw9LZ70N7p1vA=",
                },
            ),
        };
        SignaturePolicy {
            identifier: identifier.to_string(),
            hash_algorithm: DigestAlgorithm::Sha1,
            hash_base64: hash.to_string(),
            qualifier: Some(qualifier.to_string()),
        }
    }
}

/// Explicit signature policy (`SignaturePolicyId`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignaturePolicy {
    /// Policy OID, optionally prefixed with `urn:oid:` (AutoFirma's `policyIdentifier`).
    pub identifier: String,
    /// Algorithm of the policy document hash (`policyIdentifierHashAlgorithm`).
    pub hash_algorithm: DigestAlgorithm,
    /// Base64 hash of the policy document (`policyIdentifierHash`).
    pub hash_base64: String,
    /// URL of the policy document (`policyQualifier`).
    pub qualifier: Option<String>,
}

impl SignaturePolicy {
    /// Policy OID.
    pub fn oid(&self) -> Result<ObjectIdentifier> {
        let identifier = self.identifier.trim();
        let identifier = identifier
            .strip_prefix("urn:oid:")
            .or_else(|| identifier.strip_prefix("URN:OID:"))
            .unwrap_or(identifier);
        ObjectIdentifier::new(identifier).map_err(|_| Error::InvalidPolicy(self.identifier.clone()))
    }

    /// Decoded policy document hash.
    pub fn hash(&self) -> Result<Vec<u8>> {
        Base64::decode_vec(self.hash_base64.trim())
            .map_err(|_| Error::InvalidPolicy(self.hash_base64.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age19_matches_autofirma() {
        let policy = PolicyPreset::Age19.policy(SignatureFormat::Cades);
        assert_eq!(policy.oid().unwrap().to_string(), "2.16.724.1.3.1.1.2.1.9");
        assert_eq!(
            crate::digest::to_hex(&policy.hash().unwrap()),
            "1bbae8b9c7fad34f9fd37affa346c0390e9602cd"
        );
    }

    #[test]
    fn age18_hash_depends_on_format() {
        assert_ne!(
            PolicyPreset::Age18
                .policy(SignatureFormat::Xades)
                .hash_base64,
            PolicyPreset::Age18
                .policy(SignatureFormat::Cades)
                .hash_base64
        );
    }

    #[test]
    fn accepts_urn_prefix() {
        let policy = SignaturePolicy {
            identifier: "urn:oid:1.2.3".to_string(),
            hash_algorithm: DigestAlgorithm::Sha1,
            hash_base64: "AA==".to_string(),
            qualifier: None,
        };
        assert_eq!(policy.oid().unwrap().to_string(), "1.2.3");
    }
}
