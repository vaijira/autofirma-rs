//! Private keys and the certificates they belong to.

use der::Decode;
use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
use pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::PrehashSigner;
use x509_cert::Certificate;

use crate::{
    algorithm::{KeyType, oid},
    cert::CertificateInfo,
    digest::DigestAlgorithm,
    error::{Error, Result},
};

pub mod filters;

/// A private key able to produce signatures, together with its certificate chain.
///
/// Signing is split from the signature formats so that keys held elsewhere
/// (WebCrypto, smart cards, a triphase server) can implement the same trait.
pub trait SigningKey {
    /// Certificate chain, leaf first.
    fn certificate_chain(&self) -> &[Certificate];

    /// DER encoding of the leaf certificate.
    fn certificate_der(&self) -> &[u8];

    /// Type of the key.
    fn key_type(&self) -> KeyType;

    /// Signs `data`: computes its `digest` and signs it with PKCS#1 v1.5 (RSA)
    /// or ECDSA (DER encoded), like Java's `SHA512withRSA` / `SHA512withECDSA`.
    fn sign_raw(&self, digest: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>>;
}

enum PrivateKey {
    Rsa(RsaPrivateKey),
    EcP256(p256::ecdsa::SigningKey),
    EcP384(p384::ecdsa::SigningKey),
}

/// Software key loaded from a PKCS#12 keystore. The key material is zeroized on drop.
pub struct SoftKey {
    key: PrivateKey,
    chain: Vec<Certificate>,
    certificate_der: Vec<u8>,
    alias: String,
}

impl std::fmt::Debug for SoftKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftKey")
            .field("alias", &self.alias)
            .field("key_type", &self.key_type())
            .finish_non_exhaustive()
    }
}

impl SoftKey {
    /// Builds a key from a PKCS#8 `PrivateKeyInfo` and its chain (DER, leaf first).
    pub fn from_pkcs8_der(alias: &str, pkcs8: &[u8], chain_der: &[&[u8]]) -> Result<Self> {
        let info = pkcs8::PrivateKeyInfo::from_der(pkcs8).map_err(|e| Error::Key(e.to_string()))?;
        let key = match info.algorithm.oid {
            oid::RSA_ENCRYPTION => PrivateKey::Rsa(
                RsaPrivateKey::from_pkcs8_der(pkcs8).map_err(|e| Error::Key(e.to_string()))?,
            ),
            oid::EC_PUBLIC_KEY => {
                let curve = info
                    .algorithm
                    .parameters_oid()
                    .map_err(|e| Error::Key(e.to_string()))?;
                match curve {
                    oid::SECP256R1 => PrivateKey::EcP256(
                        p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8)
                            .map_err(|e| Error::Key(e.to_string()))?,
                    ),
                    oid::SECP384R1 => PrivateKey::EcP384(
                        p384::ecdsa::SigningKey::from_pkcs8_der(pkcs8)
                            .map_err(|e| Error::Key(e.to_string()))?,
                    ),
                    other => return Err(Error::UnsupportedKey(format!("curva EC {other}"))),
                }
            }
            other => return Err(Error::UnsupportedKey(other.to_string())),
        };

        let chain = chain_der
            .iter()
            .map(|der| Certificate::from_der(der).map_err(|e| Error::Certificate(e.to_string())))
            .collect::<Result<Vec<_>>>()?;
        let certificate_der = chain_der
            .first()
            .ok_or_else(|| Error::Certificate("la clave no tiene certificado".to_string()))?
            .to_vec();

        Ok(Self {
            key,
            chain,
            certificate_der,
            alias: alias.to_string(),
        })
    }

    /// Alias (friendly name) of the entry in the keystore.
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Information about the leaf certificate.
    pub fn certificate_info(&self) -> Result<CertificateInfo> {
        CertificateInfo::from_certificate(&self.chain[0], &self.certificate_der)
    }
}

impl SigningKey for SoftKey {
    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    fn key_type(&self) -> KeyType {
        match self.key {
            PrivateKey::Rsa(_) => KeyType::Rsa,
            PrivateKey::EcP256(_) => KeyType::EcP256,
            PrivateKey::EcP384(_) => KeyType::EcP384,
        }
    }

    fn sign_raw(&self, digest: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
        let hash = digest.digest(data);
        let signing_error = |e: &dyn std::fmt::Display| Error::Signing(e.to_string());
        match &self.key {
            PrivateKey::Rsa(key) => {
                let padding = match digest {
                    DigestAlgorithm::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
                    DigestAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
                    DigestAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
                    DigestAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
                };
                key.sign(padding, &hash).map_err(|e| signing_error(&e))
            }
            PrivateKey::EcP256(key) => {
                let signature: p256::ecdsa::Signature =
                    key.sign_prehash(&hash).map_err(|e| signing_error(&e))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            PrivateKey::EcP384(key) => {
                let signature: p384::ecdsa::Signature =
                    key.sign_prehash(&hash).map_err(|e| signing_error(&e))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
    }
}

/// Loads every private key (with its certificate chain) from a PKCS#12 keystore.
///
/// Supports PBES2/AES keystores and the legacy RC2/3DES ones exported by older
/// browsers and Windows.
pub fn load_pkcs12(data: &[u8], password: &str) -> Result<Vec<SoftKey>> {
    let keystore = KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Relaxed).map_err(
        |e| match e {
            p12_keystore::error::Error::MacError(_) => Error::WrongPassword,
            other => Error::Pkcs12(other.to_string()),
        },
    )?;

    let keys = keystore
        .entries()
        .filter_map(|(alias, entry)| match entry {
            p12_keystore::KeyStoreEntry::PrivateKeyChain(chain) if !chain.certs().is_empty() => {
                let certs: Vec<&[u8]> = chain.certs().iter().map(|c| c.as_der()).collect();
                Some(SoftKey::from_pkcs8_der(alias, chain.key().as_der(), &certs))
            }
            _ => None,
        })
        .collect::<Result<Vec<_>>>()?;

    if keys.is_empty() {
        return Err(Error::Pkcs12(
            "el almacén no contiene ninguna clave privada con certificado".to_string(),
        ));
    }
    Ok(keys)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn load(name: &str) -> Vec<SoftKey> {
        let path = format!(
            "{}/../../tests/data/certs/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        load_pkcs12(&std::fs::read(path).unwrap(), "1234").unwrap()
    }

    #[test]
    fn loads_rsa_keystore() {
        let keys = load("rsa.p12");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].alias(), "rsa");
        assert_eq!(keys[0].key_type(), KeyType::Rsa);
        // Leaf and test CA.
        assert_eq!(keys[0].certificate_chain().len(), 2);
    }

    #[test]
    fn loads_legacy_keystore() {
        let keys = load("rsa-legacy.p12");
        assert_eq!(keys[0].key_type(), KeyType::Rsa);
    }

    #[test]
    fn loads_ec_keystore() {
        let keys = load("ec.p12");
        assert_eq!(keys[0].key_type(), KeyType::EcP256);
        assert_eq!(
            keys[0].certificate_info().unwrap().key_type,
            Some(KeyType::EcP256)
        );
    }

    #[test]
    fn wrong_password() {
        let path = format!(
            "{}/../../tests/data/certs/rsa.p12",
            env!("CARGO_MANIFEST_DIR")
        );
        let err = load_pkcs12(&std::fs::read(path).unwrap(), "bad").unwrap_err();
        assert!(matches!(err, Error::WrongPassword), "{err:?}");
    }
}
