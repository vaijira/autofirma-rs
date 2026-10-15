//! Certificate information shown to the user and used by the filters.

use der::{Decode, Encode, asn1::Any};
use serde::{Deserialize, Serialize};
use x509_cert::{
    Certificate,
    ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, name::DirectoryString},
    name::Name,
};

use crate::{
    algorithm::{KeyType, oid},
    digest::{DigestAlgorithm, to_hex},
    error::{Error, Result},
};

/// Summary of an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Subject distinguished name (RFC 4514).
    pub subject: String,
    /// Subject common name, or the full subject if there is none.
    pub subject_cn: String,
    /// Issuer distinguished name (RFC 4514).
    pub issuer: String,
    /// Issuer common name, or the full issuer if there is none.
    pub issuer_cn: String,
    /// Serial number, upper case hex.
    pub serial: String,
    /// Start of validity, seconds since the Unix epoch.
    pub not_before: i64,
    /// End of validity, seconds since the Unix epoch.
    pub not_after: i64,
    /// Key usage allows `digitalSignature`.
    pub digital_signature: bool,
    /// Key usage allows `nonRepudiation` (content commitment).
    pub non_repudiation: bool,
    /// The certificate has no key usage extension (any usage allowed).
    pub key_usage_unrestricted: bool,
    /// The certificate belongs to a certification authority.
    pub is_ca: bool,
    /// The certificate declares QC statements (qualified certificate).
    pub qualified: bool,
    /// Type of the public key, if supported.
    pub key_type: Option<KeyType>,
    /// SHA-1 fingerprint (AutoFirma's "thumbprint"), upper case hex.
    pub sha1_fingerprint: String,
    /// SHA-256 fingerprint, upper case hex.
    pub sha256_fingerprint: String,
}

/// Validity of a certificate at a given time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidityStatus {
    /// Inside its validity period.
    Valid,
    /// Not valid yet.
    NotYetValid,
    /// Expired.
    Expired,
}

impl CertificateInfo {
    /// Extracts the information from a DER encoded certificate.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let cert = Certificate::from_der(der).map_err(|e| Error::Certificate(e.to_string()))?;
        Self::from_certificate(&cert, der)
    }

    /// Extracts the information from a parsed certificate and its DER encoding.
    pub fn from_certificate(cert: &Certificate, der: &[u8]) -> Result<Self> {
        let tbs = cert.tbs_certificate();

        let mut info = CertificateInfo {
            subject: tbs.subject().to_string(),
            subject_cn: common_name(tbs.subject()).unwrap_or_else(|| tbs.subject().to_string()),
            issuer: tbs.issuer().to_string(),
            issuer_cn: common_name(tbs.issuer()).unwrap_or_else(|| tbs.issuer().to_string()),
            serial: to_hex(tbs.serial_number().as_bytes()).to_uppercase(),
            not_before: unix_seconds(&tbs.validity().not_before),
            not_after: unix_seconds(&tbs.validity().not_after),
            digital_signature: false,
            non_repudiation: false,
            key_usage_unrestricted: true,
            is_ca: false,
            qualified: false,
            key_type: key_type(&tbs.subject_public_key_info().algorithm),
            sha1_fingerprint: to_hex(&DigestAlgorithm::Sha1.digest(der)).to_uppercase(),
            sha256_fingerprint: to_hex(&DigestAlgorithm::Sha256.digest(der)).to_uppercase(),
        };

        for ext in tbs.extensions().into_iter().flatten() {
            match ext.extn_id {
                oid::KEY_USAGE => {
                    let usage = KeyUsage::from_der(ext.extn_value.as_bytes())
                        .map_err(|e| Error::Certificate(e.to_string()))?;
                    info.key_usage_unrestricted = false;
                    info.digital_signature = usage.0.contains(KeyUsages::DigitalSignature);
                    info.non_repudiation = usage.0.contains(KeyUsages::NonRepudiation);
                }
                oid::BASIC_CONSTRAINTS => {
                    let constraints = BasicConstraints::from_der(ext.extn_value.as_bytes())
                        .map_err(|e| Error::Certificate(e.to_string()))?;
                    info.is_ca = constraints.ca;
                }
                oid::QC_STATEMENTS => info.qualified = true,
                _ => {}
            }
        }
        if info.key_usage_unrestricted {
            info.digital_signature = true;
            info.non_repudiation = true;
        }

        Ok(info)
    }

    /// Validity of the certificate at `now` (seconds since the Unix epoch).
    pub fn validity_at(&self, now: i64) -> ValidityStatus {
        if now < self.not_before {
            ValidityStatus::NotYetValid
        } else if now > self.not_after {
            ValidityStatus::Expired
        } else {
            ValidityStatus::Valid
        }
    }

    /// Whether the key usage allows creating signatures.
    pub fn can_sign(&self) -> bool {
        self.digital_signature || self.non_repudiation
    }
}

fn unix_seconds(time: &x509_cert::time::Time) -> i64 {
    i64::try_from(time.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
}

fn key_type(algorithm: &spki::AlgorithmIdentifierOwned) -> Option<KeyType> {
    match algorithm.oid {
        oid::RSA_ENCRYPTION => Some(KeyType::Rsa),
        oid::EC_PUBLIC_KEY => match algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<const_oid::ObjectIdentifier>().ok())
        {
            Some(oid::SECP256R1) => Some(KeyType::EcP256),
            Some(oid::SECP384R1) => Some(KeyType::EcP384),
            _ => None,
        },
        _ => None,
    }
}

/// Value of the last attribute of type `attr` in `name`, decoded as a string.
pub(crate) fn name_attribute(name: &Name, attr: const_oid::ObjectIdentifier) -> Option<String> {
    name.iter()
        .filter(|atv| atv.oid == attr)
        .filter_map(|atv| any_to_string(&atv.value))
        .last()
}

fn common_name(name: &Name) -> Option<String> {
    name_attribute(name, oid::COMMON_NAME)
}

fn any_to_string(value: &Any) -> Option<String> {
    let der = value.to_der().ok()?;
    if let Ok(dir) = DirectoryString::from_der(&der) {
        return Some(match dir {
            DirectoryString::PrintableString(s) => s.to_string(),
            DirectoryString::TeletexString(s) => s.to_string(),
            DirectoryString::Utf8String(s) => s,
            DirectoryString::BmpString(s) => s.to_string(),
        });
    }
    value
        .decode_as::<der::asn1::Ia5StringRef<'_>>()
        .ok()
        .map(|s| s.to_string())
        .or_else(|| {
            value
                .decode_as::<der::asn1::BmpString>()
                .ok()
                .map(|s| s.to_string())
        })
}

/// DER encoding of a parsed certificate.
pub(crate) fn to_der(cert: &Certificate) -> Result<Vec<u8>> {
    cert.to_der().map_err(|e| Error::Certificate(e.to_string()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keystore::SigningKey;

    /// Leaf certificate of `tests/data/certs/rsa.p12`.
    pub fn rsa_leaf_der() -> Vec<u8> {
        let p12 = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/data/certs/rsa.p12"
        ))
        .unwrap();
        let keys = crate::keystore::load_pkcs12(&p12, "1234").unwrap();
        keys[0].certificate_der().to_vec()
    }

    #[test]
    fn rsa_certificate_info() {
        let info = CertificateInfo::from_der(&rsa_leaf_der()).unwrap();
        assert_eq!(info.subject_cn, "ESPAÑOL ESPAÑOL JUAN - 99999999R");
        assert_eq!(info.issuer_cn, "autofirma-rs Test CA");
        assert!(
            info.subject.contains("serialNumber=IDCES-99999999R")
                || info.subject.contains("IDCES-99999999R")
        );
        assert!(info.digital_signature);
        assert!(info.non_repudiation);
        assert!(!info.key_usage_unrestricted);
        assert!(!info.is_ca);
        assert_eq!(info.key_type, Some(KeyType::Rsa));
        assert_eq!(info.sha1_fingerprint.len(), 40);
        assert_eq!(info.validity_at(info.not_before + 1), ValidityStatus::Valid);
        assert_eq!(
            info.validity_at(info.not_after + 1),
            ValidityStatus::Expired
        );
        assert_eq!(
            info.validity_at(info.not_before - 1),
            ValidityStatus::NotYetValid
        );
    }
}
