//! FacturaE electronic invoices: XAdES-EPES enveloped signatures with the
//! FacturaE signature policy, as AutoFirma's `AOFacturaESigner` makes them.
//!
//! Compared with XAdES enveloped, the data reference has only the enveloped
//! transform (no canonicalization or XPath filter), the policy is FacturaE 3.1
//! and the signer claims a role (`emisor` by default). Invoices can only be
//! signed once.

use bergshamra_xml::uppsala;
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::{
    algorithm::KeyType,
    digest::DigestAlgorithm,
    error::{Error, Result},
    keystore::SigningKey,
    policy::SignaturePolicy,
    xades::{self, PreparedXades, ProductionPlace, Profile, XadesFormat, XadesParams},
    xml::{self, DSIG_NS, XmlText},
};

/// Role of the signer of an invoice (AutoFirma's `signerClaimedRoles`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FacturaeRole {
    /// The issuer of the invoice (`emisor`, AutoFirma's default).
    #[default]
    Issuer,
    /// The receiver of the invoice (`receptor`).
    Receiver,
    /// A third party (`tercero`).
    ThirdParty,
}

impl FacturaeRole {
    /// Role as written in the signature.
    pub fn name(self) -> &'static str {
        match self {
            FacturaeRole::Issuer => "emisor",
            FacturaeRole::Receiver => "receptor",
            FacturaeRole::ThirdParty => "tercero",
        }
    }
}

/// Parameters of a FacturaE signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacturaeParams {
    /// Digest algorithm (AutoFirma's default is SHA-512).
    pub digest: DigestAlgorithm,
    /// Signing time, seconds since the Unix epoch.
    pub signing_time: i64,
    /// Local time offset from UTC in minutes, for `SigningTime`.
    pub utc_offset_minutes: i32,
    /// Role of the signer.
    pub role: FacturaeRole,
    /// Where the invoice was signed.
    pub production_place: ProductionPlace,
}

impl FacturaeParams {
    /// AutoFirma's defaults: SHA-512, signed by the issuer.
    pub fn new(signing_time: i64) -> Self {
        FacturaeParams {
            digest: DigestAlgorithm::Sha512,
            signing_time,
            utc_offset_minutes: 0,
            role: FacturaeRole::Issuer,
            production_place: ProductionPlace::default(),
        }
    }
}

/// FacturaE signature policy v3.1, the one AutoFirma uses.
pub fn policy() -> SignaturePolicy {
    SignaturePolicy {
        identifier: "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf"
            .to_string(),
        hash_algorithm: DigestAlgorithm::Sha1,
        hash_base64: "Ohixl6upD6av8N7pEvDABhEL6hM=".to_string(),
        qualifier: None,
    }
}

/// What a FacturaE file looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Invoice {
    signed: bool,
}

/// Reads `data` as an invoice: a `Facturae` root element with `FileHeader`,
/// `Parties` and `Invoices`, as AutoFirma checks it.
fn read_invoice(data: &[u8]) -> Option<Invoice> {
    let text = XmlText::decode(data).ok()?;
    let doc = uppsala::parse(&text.text).ok()?;
    let root = doc.document_element()?;
    if doc.element(root)?.name.local_name != "Facturae" {
        return None;
    }
    let children: Vec<String> = xml::child_elements(&doc, root)
        .into_iter()
        .filter_map(|child| Some(doc.element(child)?.name.local_name.to_string()))
        .collect();
    let complete = ["FileHeader", "Parties", "Invoices"]
        .iter()
        .all(|name| children.iter().any(|child| child == name));
    complete.then(|| Invoice {
        signed: xml::child(&doc, root, DSIG_NS, "Signature").is_some(),
    })
}

/// Whether `data` is a FacturaE invoice (signed or not).
pub fn is_facturae(data: &[u8]) -> bool {
    read_invoice(data).is_some()
}

/// First phase of a FacturaE signature; see [`xades::prepare`].
pub fn prepare(
    data: &[u8],
    chain: &[Certificate],
    key_type: KeyType,
    params: &FacturaeParams,
) -> Result<PreparedXades> {
    match read_invoice(data) {
        None => return Err(Error::InvalidFacturae),
        Some(Invoice { signed: true }) => return Err(Error::FacturaeAlreadySigned),
        Some(_) => {}
    }
    let xades_params = XadesParams {
        digest: params.digest,
        format: XadesFormat::Enveloped,
        policy: Some(policy()),
        signing_time: params.signing_time,
        utc_offset_minutes: params.utc_offset_minutes,
        production_place: params.production_place.clone(),
        claimed_roles: vec![params.role.name().to_string()],
    };
    xades::prepare_with(
        data,
        chain,
        key_type,
        &xades_params,
        Profile {
            canonicalize_data: false,
            xpath_filter: false,
            asic_file: None,
        },
    )
}

/// Signs a FacturaE invoice with `key`.
pub fn sign(data: &[u8], key: &dyn SigningKey, params: &FacturaeParams) -> Result<Vec<u8>> {
    let prepared = prepare(data, key.certificate_chain(), key.key_type(), params)?;
    let signature = key.sign_raw(params.digest, prepared.to_be_signed())?;
    prepared.finish(&signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::tests::load;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/data/xades/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn signs_like_autofirma() {
        let invoice = fixture("factura.xml");
        assert!(is_facturae(&invoice));
        assert!(!is_facturae(&fixture("doc.xml")));

        let key = &load("rsa.p12")[0];
        let params = FacturaeParams {
            utc_offset_minutes: 120,
            ..FacturaeParams::new(1_792_428_983)
        };
        let signed = sign(&invoice, key, &params).unwrap();
        let report = xades::verify(&signed, None).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.signatures[0].claimed_roles, ["emisor"]);
        assert_eq!(
            report.signatures[0].signer.policy.as_deref(),
            Some(policy().identifier.as_str())
        );

        // Same reference transforms and policy as AutoFirma's.
        let ours = String::from_utf8(signed.clone()).unwrap();
        let theirs = String::from_utf8(fixture("autofirma-facturae-rsa.xsig")).unwrap();
        let part = |text: &str, start: &str, end: &str| {
            let from = text.find(start).unwrap();
            text[from..from + text[from..].find(end).unwrap()].to_string()
        };
        assert_eq!(
            part(&ours, "<ds:Transforms>", "</ds:Transforms>"),
            part(&theirs, "<ds:Transforms>", "</ds:Transforms>")
        );
        assert_eq!(
            part(
                &ours,
                "<xades:SignaturePolicyIdentifier>",
                "</xades:SignerRole>"
            ),
            part(
                &theirs,
                "<xades:SignaturePolicyIdentifier>",
                "</xades:SignerRole>"
            )
        );

        assert!(matches!(
            sign(&signed, key, &params),
            Err(Error::FacturaeAlreadySigned)
        ));
        assert!(matches!(
            sign(&fixture("doc.xml"), key, &params),
            Err(Error::InvalidFacturae)
        ));
    }
}
