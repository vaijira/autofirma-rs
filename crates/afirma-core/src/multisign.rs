//! Co-signatures and counter-signatures of existing signatures, whatever their
//! format (AutoFirma's `cosign` and `countersign` operations).
//!
//! * CAdES and XAdES: [`crate::cades::cosign`], [`crate::xades::cosign`] and
//!   their `countersign` counterparts.
//! * ASiC-S: the signature inside the container, which is then rebuilt.
//! * ODF and OOXML: a co-signature is one more signature of the document;
//!   they have no counter-signatures.
//! * PDF: a co-signature is a new PAdES signature ([`crate::pades::sign`]).

use serde::{Deserialize, Serialize};

use crate::{
    asic::{self, AsicFormat},
    cades::{self, CadesParams, SignatureMode},
    digest::DigestAlgorithm,
    error::{Error, Result},
    facturae,
    format::{DataKind, SignatureFormat},
    keystore::SigningKey,
    odf::{self, OdfParams},
    ooxml::{self, OoxmlParams},
    policy::PolicyPreset,
    xades::{self, ProductionPlace, XadesParams},
};

/// Signers to counter-sign (AutoFirma's `CounterSignTarget`; the `nodes` and
/// `signers` targets are no longer supported by AutoFirma either).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CounterSignTarget {
    /// Every signature, counter-signatures included (`tree`).
    Tree,
    /// The signatures that are not counter-signed yet (`leafs`, AutoFirma's default).
    #[default]
    Leafs,
}

impl CounterSignTarget {
    /// Name used in AutoFirma's `target` parameter.
    pub fn name(self) -> &'static str {
        match self {
            CounterSignTarget::Tree => "tree",
            CounterSignTarget::Leafs => "leafs",
        }
    }
}

/// Operation on an existing signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiSignOperation {
    /// Add a signer over the same data.
    Cosign,
    /// Sign the signature value of existing signers.
    Countersign(CounterSignTarget),
}

/// Options of a co-signature or counter-signature. The format is that of the
/// existing signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiSignParams {
    /// Digest algorithm.
    pub digest: DigestAlgorithm,
    /// CAdES: embed the data when a co-signature of an explicit signature is
    /// given the data.
    pub mode: SignatureMode,
    /// AGE signature policy (EPES), in the variant of the signature's format.
    pub policy: Option<PolicyPreset>,
    /// Signing time, seconds since the Unix epoch.
    pub signing_time: i64,
    /// Local time offset from UTC in minutes (XML formats).
    pub utc_offset_minutes: i32,
    /// Where the signature was made (XML formats).
    pub production_place: ProductionPlace,
    /// Roles claimed by the signer (XML formats).
    pub claimed_roles: Vec<String>,
}

impl MultiSignParams {
    /// AutoFirma's defaults: SHA-512 without policy.
    pub fn new(signing_time: i64) -> Self {
        MultiSignParams {
            digest: DigestAlgorithm::Sha512,
            mode: SignatureMode::Explicit,
            policy: None,
            signing_time,
            utc_offset_minutes: 0,
            production_place: ProductionPlace::default(),
            claimed_roles: Vec::new(),
        }
    }

    /// CAdES parameters; `content` describes the `contentHint` of co-signatures.
    pub fn cades(&self, content: Option<&[u8]>) -> CadesParams {
        CadesParams {
            digest: self.digest,
            mode: self.mode,
            policy: self
                .policy
                .map(|preset| preset.policy(SignatureFormat::Cades)),
            signing_time: self.signing_time,
            content_description: content
                .map(DataKind::detect)
                .filter(|kind| *kind != DataKind::Binary)
                .map(|kind| kind.description().to_string()),
        }
    }

    /// ODF parameters.
    pub fn odf(&self) -> OdfParams {
        OdfParams {
            digest: self.digest,
            signing_time: self.signing_time,
            utc_offset_minutes: self.utc_offset_minutes,
        }
    }

    /// OOXML parameters.
    pub fn ooxml(&self) -> OoxmlParams {
        OoxmlParams {
            digest: self.digest,
            signing_time: self.signing_time,
            utc_offset_minutes: self.utc_offset_minutes,
            production_place: self.production_place.clone(),
            claimed_roles: self.claimed_roles.clone(),
            comments: None,
        }
    }

    /// XAdES parameters.
    pub fn xades(&self) -> XadesParams {
        XadesParams {
            digest: self.digest,
            policy: self
                .policy
                .map(|preset| preset.policy(SignatureFormat::Xades)),
            utc_offset_minutes: self.utc_offset_minutes,
            production_place: self.production_place.clone(),
            claimed_roles: self.claimed_roles.clone(),
            ..XadesParams::new(self.signing_time)
        }
    }
}

/// Name of a co-signed or counter-signed file: `firma.csig` →
/// `firma_cosigned.csig` / `firma_countersigned.csig`.
pub fn multisigned_file_name(name: &str, operation: MultiSignOperation) -> String {
    let suffix = match operation {
        MultiSignOperation::Cosign => "_cosigned",
        MultiSignOperation::Countersign(_) => "_countersigned",
    };
    match name.rsplit_once('.').filter(|(stem, _)| !stem.is_empty()) {
        Some((stem, extension)) => format!("{stem}{suffix}.{extension}"),
        None => format!("{name}{suffix}"),
    }
}

/// Format of an existing signature, as far as multi-signatures are concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignedKind {
    /// CAdES / CMS.
    Cades,
    /// XAdES / XMLDSig.
    Xades,
    /// FacturaE invoice (XAdES; counter-signatures only).
    Facturae,
    /// ASiC-S container.
    Asic,
    /// Signed PDF.
    Pdf,
    /// Signed ODF document.
    Odf,
    /// Signed OOXML document.
    Ooxml,
}

impl SignedKind {
    /// Kind of signature in `data`, if it is a signature or a signed document.
    pub fn detect(data: &[u8]) -> Option<Self> {
        match DataKind::detect(data) {
            DataKind::CmsSignedData => Some(SignedKind::Cades),
            DataKind::Xml if facturae::is_facturae(data) => {
                xades::is_signed(data).then_some(SignedKind::Facturae)
            }
            DataKind::Xml => xades::is_signed(data).then_some(SignedKind::Xades),
            DataKind::Zip => asic::is_asic(data).then_some(SignedKind::Asic),
            DataKind::Odf => odf::is_signed(data).then_some(SignedKind::Odf),
            DataKind::Ooxml => ooxml::is_signed(data).then_some(SignedKind::Ooxml),
            DataKind::Pdf => crate::pades::is_signed(data).then_some(SignedKind::Pdf),
            DataKind::Text | DataKind::Binary => None,
        }
    }

    /// Whether the format has counter-signatures.
    pub fn can_countersign(self) -> bool {
        matches!(
            self,
            SignedKind::Cades | SignedKind::Xades | SignedKind::Facturae | SignedKind::Asic
        )
    }
}

/// Co-signs or counter-signs `signature`, keeping its format.
///
/// `data` is the signed data, needed to co-sign some explicit CAdES signatures.
pub fn multisign(
    signature: &[u8],
    data: Option<&[u8]>,
    operation: MultiSignOperation,
    key: &dyn SigningKey,
    params: &MultiSignParams,
) -> Result<Vec<u8>> {
    let kind = SignedKind::detect(signature).ok_or_else(|| {
        Error::InvalidSignature("el fichero no es una firma ni un documento firmado".to_string())
    })?;
    match (kind, operation) {
        (SignedKind::Cades, MultiSignOperation::Cosign) => {
            let content = match data {
                Some(data) => Some(data.to_vec()),
                None => cades::embedded_content(signature)?,
            };
            cades::cosign(signature, data, key, &params.cades(content.as_deref()))
        }
        (SignedKind::Cades, MultiSignOperation::Countersign(target)) => {
            cades::countersign(signature, target, key, &params.cades(None))
        }
        (SignedKind::Xades, MultiSignOperation::Cosign) => {
            xades::cosign(signature, data, key, &params.xades())
        }
        (SignedKind::Facturae, MultiSignOperation::Cosign) => Err(Error::FacturaeAlreadySigned),
        (SignedKind::Xades | SignedKind::Facturae, MultiSignOperation::Countersign(target)) => {
            xades::countersign(signature, target, key, &params.xades())
        }
        (SignedKind::Asic, operation) => {
            let container = asic::open(signature)?;
            let inner = match (container.format, operation) {
                (AsicFormat::Cades, MultiSignOperation::Cosign) => cades::cosign(
                    &container.signature,
                    Some(&container.data),
                    key,
                    // The CAdES signature of a container is always explicit.
                    &CadesParams {
                        mode: SignatureMode::Explicit,
                        ..params.cades(Some(&container.data))
                    },
                )?,
                (AsicFormat::Cades, MultiSignOperation::Countersign(target)) => {
                    cades::countersign(&container.signature, target, key, &params.cades(None))?
                }
                (AsicFormat::Xades, MultiSignOperation::Cosign) => xades::cosign(
                    &container.signature,
                    Some(&container.data),
                    key,
                    &params.xades(),
                )?,
                (AsicFormat::Xades, MultiSignOperation::Countersign(target)) => {
                    xades::countersign(&container.signature, target, key, &params.xades())?
                }
            };
            container.repackage(&inner)
        }
        (SignedKind::Odf, MultiSignOperation::Cosign) => odf::sign(signature, key, &params.odf()),
        (SignedKind::Ooxml, MultiSignOperation::Cosign) => {
            ooxml::sign(signature, key, &params.ooxml())
        }
        (SignedKind::Pdf, MultiSignOperation::Cosign) => Err(Error::Unsupported(
            "los PDF se cofirman con una nueva firma PAdES".to_string(),
        )),
        (
            SignedKind::Odf | SignedKind::Ooxml | SignedKind::Pdf,
            MultiSignOperation::Countersign(_),
        ) => Err(Error::Unsupported(
            "este formato no admite contrafirmas".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keystore::tests::load, validation};

    fn fixture(path: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/data/{path}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn asic_containers_keep_their_format() {
        let key = &load("ec.p12")[0];
        let params = MultiSignParams {
            policy: Some(PolicyPreset::Age19),
            ..MultiSignParams::new(1_792_428_983)
        };
        for name in [
            "asic/autofirma-cades-rsa.asics",
            "asic/autofirma-xades-rsa.asics",
        ] {
            for operation in [
                MultiSignOperation::Cosign,
                MultiSignOperation::Countersign(CounterSignTarget::Leafs),
            ] {
                let signed = multisign(&fixture(name), None, operation, key, &params).unwrap();
                assert_eq!(SignedKind::detect(&signed), Some(SignedKind::Asic));
                let verification = validation::verify(&signed, None, None).unwrap();
                assert!(
                    verification.is_valid(),
                    "{name} {operation:?}: {verification:?}"
                );
                let report = format!("{verification:?}");
                assert_eq!(report.matches("certificate: Some").count(), 2, "{name}");
            }
        }
    }

    #[test]
    fn rejects_what_cannot_be_done() {
        let key = &load("rsa.p12")[0];
        let params = MultiSignParams::new(1_792_428_983);
        let invoice = fixture("xades/autofirma-facturae-rsa.xsig");
        assert_eq!(SignedKind::detect(&invoice), Some(SignedKind::Facturae));
        assert!(matches!(
            multisign(&invoice, None, MultiSignOperation::Cosign, key, &params),
            Err(Error::FacturaeAlreadySigned)
        ));
        assert!(matches!(
            multisign(b"hola", None, MultiSignOperation::Cosign, key, &params),
            Err(Error::InvalidSignature(_))
        ));
        let odt = fixture("odf/autofirma-rsa.odt");
        assert!(!SignedKind::Odf.can_countersign());
        assert!(matches!(
            multisign(
                &odt,
                None,
                MultiSignOperation::Countersign(CounterSignTarget::Tree),
                key,
                &params
            ),
            Err(Error::Unsupported(_))
        ));
        assert!(multisign(&odt, None, MultiSignOperation::Cosign, key, &params).is_ok());
    }

    #[test]
    fn file_names() {
        assert_eq!(
            multisigned_file_name("firma.csig", MultiSignOperation::Cosign),
            "firma_cosigned.csig"
        );
        assert_eq!(
            multisigned_file_name(
                "doc.xml.xsig",
                MultiSignOperation::Countersign(CounterSignTarget::Tree)
            ),
            "doc.xml_countersigned.xsig"
        );
        assert_eq!(
            multisigned_file_name("firma", MultiSignOperation::Cosign),
            "firma_cosigned"
        );
    }
}
