//! Signature algorithms and their object identifiers.

use const_oid::ObjectIdentifier;
use der::asn1::Any;
use serde::{Deserialize, Serialize};
use spki::AlgorithmIdentifierOwned;

use crate::digest::DigestAlgorithm;

/// Object identifiers used by the signature formats.
pub mod oid {
    use const_oid::ObjectIdentifier;

    /// id-data (1.2.840.113549.1.7.1).
    pub const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
    /// id-signedData (1.2.840.113549.1.7.2).
    pub const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

    /// id-contentType signed attribute.
    pub const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
    /// id-messageDigest signed attribute.
    pub const MESSAGE_DIGEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
    /// id-signingTime signed attribute.
    pub const SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
    /// id-aa-contentHint signed attribute (RFC 2634).
    pub const CONTENT_HINT: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.4");
    /// id-aa-ets-sigPolicyId signed attribute (RFC 5126).
    pub const SIGNATURE_POLICY_ID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.15");
    /// id-aa-signingCertificateV2 signed attribute (RFC 5035).
    pub const SIGNING_CERTIFICATE_V2: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
    /// id-spq-ets-uri policy qualifier.
    pub const SPQ_ETS_URI: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.5.1");

    /// SHA-1.
    pub const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    /// SHA-256.
    pub const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    /// SHA-384.
    pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
    /// SHA-512.
    pub const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

    /// rsaEncryption.
    pub const RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    /// sha1WithRSAEncryption.
    pub const SHA1_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
    /// sha256WithRSAEncryption.
    pub const SHA256_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    /// sha384WithRSAEncryption.
    pub const SHA384_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    /// sha512WithRSAEncryption.
    pub const SHA512_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

    /// id-ecPublicKey.
    pub const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    /// secp256r1 / prime256v1.
    pub const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    /// secp384r1.
    pub const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
    /// ecdsa-with-SHA1.
    pub const ECDSA_WITH_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");
    /// ecdsa-with-SHA256.
    pub const ECDSA_WITH_SHA256: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    /// ecdsa-with-SHA384.
    pub const ECDSA_WITH_SHA384: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    /// ecdsa-with-SHA512.
    pub const ECDSA_WITH_SHA512: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

    /// Key usage certificate extension.
    pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
    /// Basic constraints certificate extension.
    pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    /// QC statements certificate extension (qualified certificates).
    pub const QC_STATEMENTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.3");
    /// Common name attribute.
    pub const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
    /// Organizational unit attribute.
    pub const ORGANIZATIONAL_UNIT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
}

/// Kind of private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// RSA.
    Rsa,
    /// ECDSA over NIST P-256.
    EcP256,
    /// ECDSA over NIST P-384.
    EcP384,
}

impl KeyType {
    /// Short description (`RSA`, `EC P-256`...).
    pub fn name(self) -> &'static str {
        match self {
            KeyType::Rsa => "RSA",
            KeyType::EcP256 => "EC P-256",
            KeyType::EcP384 => "EC P-384",
        }
    }
}

impl DigestAlgorithm {
    /// Object identifier of the digest algorithm.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            DigestAlgorithm::Sha1 => oid::SHA1,
            DigestAlgorithm::Sha256 => oid::SHA256,
            DigestAlgorithm::Sha384 => oid::SHA384,
            DigestAlgorithm::Sha512 => oid::SHA512,
        }
    }

    /// Algorithm identifier with NULL parameters, as AutoFirma encodes it.
    pub fn algorithm_identifier(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: Some(Any::null()),
        }
    }

    /// Digest algorithm for an object identifier.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        [Self::Sha1, Self::Sha256, Self::Sha384, Self::Sha512]
            .into_iter()
            .find(|digest| digest.oid() == *oid)
    }
}

/// Algorithm identifier of the signature value in a CMS `SignerInfo`.
///
/// Like AutoFirma, RSA signatures use `rsaEncryption` and ECDSA signatures
/// `ecdsa-with-SHAxxx`.
pub fn cms_signature_algorithm(key: KeyType, digest: DigestAlgorithm) -> AlgorithmIdentifierOwned {
    match key {
        KeyType::Rsa => AlgorithmIdentifierOwned {
            oid: oid::RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        },
        KeyType::EcP256 | KeyType::EcP384 => AlgorithmIdentifierOwned {
            oid: match digest {
                DigestAlgorithm::Sha1 => oid::ECDSA_WITH_SHA1,
                DigestAlgorithm::Sha256 => oid::ECDSA_WITH_SHA256,
                DigestAlgorithm::Sha384 => oid::ECDSA_WITH_SHA384,
                DigestAlgorithm::Sha512 => oid::ECDSA_WITH_SHA512,
            },
            parameters: Some(Any::null()),
        },
    }
}

/// Digest algorithm implied by a signature algorithm OID, if any
/// (`sha256WithRSAEncryption` → SHA-256, `rsaEncryption` → `None`).
pub fn digest_of_signature_algorithm(oid: &ObjectIdentifier) -> Option<DigestAlgorithm> {
    match *oid {
        oid::SHA1_WITH_RSA | oid::ECDSA_WITH_SHA1 => Some(DigestAlgorithm::Sha1),
        oid::SHA256_WITH_RSA | oid::ECDSA_WITH_SHA256 => Some(DigestAlgorithm::Sha256),
        oid::SHA384_WITH_RSA | oid::ECDSA_WITH_SHA384 => Some(DigestAlgorithm::Sha384),
        oid::SHA512_WITH_RSA | oid::ECDSA_WITH_SHA512 => Some(DigestAlgorithm::Sha512),
        _ => None,
    }
}
