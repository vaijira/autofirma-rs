//! Certificate filters, a subset of AutoFirma's `filter` / `filters` extra parameters.
//!
//! Supported expressions (case insensitive keywords):
//!
//! | Expression | Matches certificates… |
//! |---|---|
//! | `nonexpired:` | inside their validity period |
//! | `signingcert:` | whose key usage allows signing, and that are not CA certificates |
//! | `qualified:` | with QC statements |
//! | `dnie:` | issued by the Spanish DNIe authority |
//! | `subject.contains:TEXT` | whose subject contains `TEXT` |
//! | `issuer.contains:TEXT` | whose issuer contains `TEXT` |
//! | `keyusage.digitalsignature:true` | with the `digitalSignature` key usage |
//! | `keyusage.nonrepudiation:true` | with the `nonRepudiation` key usage |
//! | `thumbprint:SHA1:HEX` / `thumbprint:SHA256:HEX` | with that fingerprint |
//!
//! Several filters can be combined with `;` and all of them must match.

use serde::{Deserialize, Serialize};

use crate::{
    cert::{CertificateInfo, ValidityStatus},
    error::{Error, Result},
};

/// A single certificate filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertFilter {
    /// Inside the validity period.
    NonExpired,
    /// Key usage allows signing and it is not a CA certificate.
    SigningCert,
    /// Qualified certificate (QC statements).
    Qualified,
    /// Issued by the DNIe authority.
    Dnie,
    /// Subject contains the text (case insensitive).
    SubjectContains(String),
    /// Issuer contains the text (case insensitive).
    IssuerContains(String),
    /// `digitalSignature` key usage.
    DigitalSignature,
    /// `nonRepudiation` key usage.
    NonRepudiation,
    /// SHA-1 fingerprint (hex, case insensitive).
    Sha1Thumbprint(String),
    /// SHA-256 fingerprint (hex, case insensitive).
    Sha256Thumbprint(String),
}

impl CertFilter {
    /// Whether `cert` passes the filter at time `now` (seconds since the Unix epoch).
    pub fn matches(&self, cert: &CertificateInfo, now: i64) -> bool {
        match self {
            CertFilter::NonExpired => cert.validity_at(now) == ValidityStatus::Valid,
            CertFilter::SigningCert => cert.can_sign() && !cert.is_ca,
            CertFilter::Qualified => cert.qualified,
            CertFilter::Dnie => {
                contains(&cert.issuer, "OU=DNIE") || contains(&cert.issuer, "CN=AC DNIE")
            }
            CertFilter::SubjectContains(text) => contains(&cert.subject, text),
            CertFilter::IssuerContains(text) => contains(&cert.issuer, text),
            CertFilter::DigitalSignature => cert.digital_signature,
            CertFilter::NonRepudiation => cert.non_repudiation,
            CertFilter::Sha1Thumbprint(hex) => same_hex(&cert.sha1_fingerprint, hex),
            CertFilter::Sha256Thumbprint(hex) => same_hex(&cert.sha256_fingerprint, hex),
        }
    }

    /// Parses one filter expression.
    pub fn parse(expression: &str) -> Result<Self> {
        let invalid = || Error::InvalidFilter(expression.to_string());
        let (keyword, value) = expression.trim().split_once(':').ok_or_else(invalid)?;
        let value = value.trim();
        let filter = match keyword.trim().to_ascii_lowercase().as_str() {
            "nonexpired" => CertFilter::NonExpired,
            "signingcert" => CertFilter::SigningCert,
            "qualified" => CertFilter::Qualified,
            "dnie" => CertFilter::Dnie,
            "subject.contains" if !value.is_empty() => {
                CertFilter::SubjectContains(value.to_string())
            }
            "issuer.contains" if !value.is_empty() => CertFilter::IssuerContains(value.to_string()),
            "keyusage.digitalsignature" if value.eq_ignore_ascii_case("true") => {
                CertFilter::DigitalSignature
            }
            "keyusage.nonrepudiation" if value.eq_ignore_ascii_case("true") => {
                CertFilter::NonRepudiation
            }
            "thumbprint" => {
                let (algorithm, hex) = value.split_once(':').ok_or_else(invalid)?;
                let hex = hex.trim().to_string();
                match algorithm
                    .trim()
                    .to_ascii_uppercase()
                    .replace('-', "")
                    .as_str()
                {
                    "SHA1" => CertFilter::Sha1Thumbprint(hex),
                    "SHA256" => CertFilter::Sha256Thumbprint(hex),
                    _ => return Err(invalid()),
                }
            }
            _ => return Err(invalid()),
        };
        Ok(filter)
    }

    /// Parses several filter expressions separated by `;`.
    pub fn parse_all(expressions: &str) -> Result<Vec<Self>> {
        expressions
            .split(';')
            .filter(|e| !e.trim().is_empty())
            .map(Self::parse)
            .collect()
    }
}

/// Whether `cert` passes every filter in `filters`.
pub fn matches_all(filters: &[CertFilter], cert: &CertificateInfo, now: i64) -> bool {
    filters.iter().all(|filter| filter.matches(cert, now))
}

fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn same_hex(a: &str, b: &str) -> bool {
    let clean = |s: &str| {
        s.chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_ascii_uppercase()
    };
    clean(a) == clean(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::tests::rsa_leaf_der;

    #[test]
    fn parses_expressions() {
        assert_eq!(
            CertFilter::parse_all("nonexpired:; subject.contains:Juan;thumbprint:SHA-1:ab cd")
                .unwrap(),
            vec![
                CertFilter::NonExpired,
                CertFilter::SubjectContains("Juan".to_string()),
                CertFilter::Sha1Thumbprint("ab cd".to_string()),
            ]
        );
        assert!(CertFilter::parse("unknown:x").is_err());
        assert!(CertFilter::parse("subject.contains:").is_err());
    }

    #[test]
    fn filters_rsa_certificate() {
        let cert = CertificateInfo::from_der(&rsa_leaf_der()).unwrap();
        let now = cert.not_before + 10;

        let filters =
            CertFilter::parse_all("nonexpired:;signingcert:;subject.contains:español").unwrap();
        assert!(matches_all(&filters, &cert, now));
        assert!(!CertFilter::NonExpired.matches(&cert, cert.not_after + 1));
        assert!(CertFilter::IssuerContains("test ca".to_string()).matches(&cert, now));
        assert!(!CertFilter::Dnie.matches(&cert, now));
        assert!(!CertFilter::Qualified.matches(&cert, now));
        assert!(
            CertFilter::Sha1Thumbprint(cert.sha1_fingerprint.to_lowercase()).matches(&cert, now)
        );
        assert!(!CertFilter::Sha256Thumbprint("00".to_string()).matches(&cert, now));
    }
}
