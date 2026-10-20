//! Signing many files at once, like AutoFirma's `afirma-core-massive`: every
//! file is signed, co-signed or counter-signed with the same key and options,
//! and the results go into a ZIP file. A file that cannot be processed is
//! reported and left out; the others are still signed.

use std::io::{Cursor, Write};

use serde::{Deserialize, Serialize};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    cades::{self, CadesParams, SignatureMode},
    digest::DigestAlgorithm,
    error::{Error, Result},
    facturae::{self, FacturaeParams, FacturaeRole},
    format::{DataKind, SignatureFormat},
    keystore::SigningKey,
    multisign::{
        self, CounterSignTarget, MultiSignOperation, MultiSignParams, SignedKind,
        multisigned_file_name,
    },
    odf::{self, OdfParams},
    ooxml::{self, OoxmlParams},
    pades::{self, PadesParams},
    policy::PolicyPreset,
    xades::{self, ProductionPlace, XadesFormat, XadesParams},
};

/// What to do with every file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MassiveOperation {
    /// Sign the files.
    Sign,
    /// Co-sign signatures (signed PDF, ODF and OOXML documents get one more signature).
    Cosign,
    /// Counter-sign signatures.
    Countersign(CounterSignTarget),
}

/// Options shared by every file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MassiveParams {
    /// Operation.
    pub operation: MassiveOperation,
    /// Signature format; `None` for AutoFirma's default for each file (PAdES for
    /// PDF, XAdES for XML, FacturaE for invoices, ODF, OOXML, CAdES otherwise).
    pub format: Option<SignatureFormat>,
    /// Digest algorithm.
    pub digest: DigestAlgorithm,
    /// AGE signature policy (not for ODF and OOXML).
    pub policy: Option<PolicyPreset>,
    /// Signing time, seconds since the Unix epoch.
    pub signing_time: i64,
    /// Local time offset from UTC in minutes.
    pub utc_offset_minutes: i32,
    /// CAdES: explicit or implicit.
    pub cades_mode: SignatureMode,
    /// XAdES: enveloping, enveloped (XML files only; others are enveloping) or detached.
    pub xades_format: XadesFormat,
    /// Reason of PDF signatures.
    pub reason: Option<String>,
    /// Where the signatures are made.
    pub location: Option<String>,
}

impl MassiveParams {
    /// AutoFirma's defaults: sign with the default format of each file, SHA-512.
    pub fn new(signing_time: i64) -> Self {
        MassiveParams {
            operation: MassiveOperation::Sign,
            format: None,
            digest: DigestAlgorithm::Sha512,
            policy: None,
            signing_time,
            utc_offset_minutes: 0,
            cades_mode: SignatureMode::Explicit,
            xades_format: XadesFormat::Enveloping,
            reason: None,
            location: None,
        }
    }

    fn production_place(&self) -> ProductionPlace {
        ProductionPlace {
            city: self.location.clone(),
            ..ProductionPlace::default()
        }
    }
}

/// A file to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MassiveFile {
    /// File name.
    pub name: String,
    /// Contents.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// What happened to a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileResult {
    /// Name of the file.
    pub name: String,
    /// Name of the result inside the ZIP file, or why the file was left out.
    pub result: std::result::Result<String, String>,
}

/// Results of signing many files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MassiveResult {
    /// ZIP file with the signatures or signed documents.
    #[serde(with = "serde_bytes")]
    pub zip: Vec<u8>,
    /// One result per file, in order.
    pub results: Vec<FileResult>,
}

impl MassiveResult {
    /// Number of files signed.
    pub fn signed(&self) -> usize {
        self.results.iter().filter(|r| r.result.is_ok()).count()
    }
}

/// Signs `files` with `key` and puts the results in a ZIP file.
pub fn sign_all(
    files: &[MassiveFile],
    key: &dyn SigningKey,
    params: &MassiveParams,
) -> Result<MassiveResult> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let zip_error = |e: zip::result::ZipError| Error::InvalidPackage(e.to_string());
    let mut names: Vec<String> = Vec::new();
    let mut results = Vec::with_capacity(files.len());
    for file in files {
        let base_name = file
            .name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_string();
        let result = sign_one(&base_name, &file.data, key, params).and_then(|(name, signed)| {
            let name = unique_name(&names, &name);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .large_file(signed.len() as u64 >= u64::from(u32::MAX));
            zip.start_file(name.as_str(), options).map_err(zip_error)?;
            zip.write_all(&signed)
                .map_err(|e| Error::InvalidPackage(e.to_string()))?;
            names.push(name.clone());
            Ok(name)
        });
        results.push(FileResult {
            name: file.name.clone(),
            result: result.map_err(|e| e.to_string()),
        });
    }
    Ok(MassiveResult {
        zip: zip.finish().map_err(zip_error)?.into_inner(),
        results,
    })
}

/// `name`, or `name (2)`, `name (3)`... if it is already in `names`.
fn unique_name(names: &[String], name: &str) -> String {
    if !names.iter().any(|n| n == name) {
        return name.to_string();
    }
    let (stem, extension) = match name.rsplit_once('.').filter(|(stem, _)| !stem.is_empty()) {
        Some((stem, extension)) => (stem, format!(".{extension}")),
        None => (name, String::new()),
    };
    (2..)
        .map(|n| format!("{stem} ({n}){extension}"))
        .find(|candidate| !names.iter().any(|n| n == candidate))
        .expect("free name")
}

/// Signs one file: the name of the result and its contents.
fn sign_one(
    name: &str,
    data: &[u8],
    key: &dyn SigningKey,
    params: &MassiveParams,
) -> Result<(String, Vec<u8>)> {
    if data.is_empty() {
        return Err(Error::EmptyData);
    }
    let multi = MultiSignParams {
        digest: params.digest,
        mode: params.cades_mode,
        policy: params.policy,
        signing_time: params.signing_time,
        utc_offset_minutes: params.utc_offset_minutes,
        production_place: params.production_place(),
        claimed_roles: Vec::new(),
    };
    let operation = match params.operation {
        MassiveOperation::Sign => {
            let format = params.format.unwrap_or_else(|| default_format(data));
            return Ok((
                format.signed_file_name(name),
                sign_data(data, format, key, params)?,
            ));
        }
        MassiveOperation::Cosign => MultiSignOperation::Cosign,
        MassiveOperation::Countersign(target) => MultiSignOperation::Countersign(target),
    };
    // Co-signing a PDF is signing it again.
    let signed = if operation == MultiSignOperation::Cosign
        && SignedKind::detect(data) == Some(SignedKind::Pdf)
    {
        sign_data(data, SignatureFormat::Pades, key, params)?
    } else {
        multisign::multisign(data, None, operation, key, &multi)?
    };
    Ok((multisigned_file_name(name, operation), signed))
}

/// AutoFirma's default format for `data`.
fn default_format(data: &[u8]) -> SignatureFormat {
    let kind = DataKind::detect(data);
    if kind == DataKind::Xml && facturae::is_facturae(data) && !xades::is_signed(data) {
        SignatureFormat::Facturae
    } else {
        kind.default_format()
    }
}

fn sign_data(
    data: &[u8],
    format: SignatureFormat,
    key: &dyn SigningKey,
    params: &MassiveParams,
) -> Result<Vec<u8>> {
    let policy = |format| params.policy.map(|preset| preset.policy(format));
    let kind = DataKind::detect(data);
    match format {
        SignatureFormat::Cades => cades::sign(
            data,
            key,
            &CadesParams {
                digest: params.digest,
                mode: params.cades_mode,
                policy: policy(SignatureFormat::Cades),
                signing_time: params.signing_time,
                content_description: (kind != DataKind::Binary)
                    .then(|| kind.description().to_string()),
            },
        ),
        SignatureFormat::Xades => xades::sign(
            data,
            key,
            &XadesParams {
                digest: params.digest,
                // Enveloped signatures need XML.
                format: match params.xades_format {
                    XadesFormat::Enveloped if kind != DataKind::Xml => XadesFormat::Enveloping,
                    format => format,
                },
                policy: policy(SignatureFormat::Xades),
                signing_time: params.signing_time,
                utc_offset_minutes: params.utc_offset_minutes,
                production_place: params.production_place(),
                claimed_roles: Vec::new(),
            },
        ),
        SignatureFormat::Facturae => facturae::sign(
            data,
            key,
            &FacturaeParams {
                digest: params.digest,
                signing_time: params.signing_time,
                utc_offset_minutes: params.utc_offset_minutes,
                role: FacturaeRole::Issuer,
                production_place: params.production_place(),
            },
        ),
        SignatureFormat::Pades => pades::sign(
            data,
            key,
            &PadesParams {
                digest: params.digest,
                policy: policy(SignatureFormat::Pades),
                utc_offset_minutes: params.utc_offset_minutes,
                reason: params.reason.clone(),
                location: params.location.clone(),
                ..PadesParams::new(params.signing_time)
            },
        ),
        SignatureFormat::Odf => odf::sign(
            data,
            key,
            &OdfParams {
                digest: params.digest,
                signing_time: params.signing_time,
                utc_offset_minutes: params.utc_offset_minutes,
            },
        ),
        SignatureFormat::Ooxml => ooxml::sign(
            data,
            key,
            &OoxmlParams {
                digest: params.digest,
                utc_offset_minutes: params.utc_offset_minutes,
                production_place: params.production_place(),
                ..OoxmlParams::new(params.signing_time)
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keystore::tests::load, package::Package, validation};

    fn fixture(path: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/data/{path}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn file(name: &str, data: Vec<u8>) -> MassiveFile {
        MassiveFile {
            name: name.to_string(),
            data,
        }
    }

    #[test]
    fn signs_every_kind_with_its_default_format() {
        let key = &load("rsa.p12")[0];
        let files = vec![
            file("dir/doc.txt", fixture("xades/doc.txt")),
            file("doc.xml", fixture("xades/doc.xml")),
            file("factura.xml", fixture("xades/factura.xml")),
            file("doc.pdf", fixture("pades/doc.pdf")),
            file("cifrado.pdf", fixture("pades/doc-aes256.pdf")),
            file("doc.txt", fixture("xades/doc.txt")),
            file("vacío", Vec::new()),
            file("doc.odt", crate::odf::tests::odt()),
            file("doc.docx", crate::ooxml::tests::docx()),
        ];
        let result = sign_all(&files, key, &MassiveParams::new(1_792_428_983)).unwrap();
        let outputs: Vec<Option<&str>> = result
            .results
            .iter()
            .map(|r| r.result.as_deref().ok())
            .collect();
        assert_eq!(
            outputs,
            [
                Some("doc.txt.csig"),
                Some("doc.xml.xsig"),
                Some("factura.xml.xsig"),
                Some("doc_signed.pdf"),
                None,
                Some("doc.txt (2).csig"),
                None,
                Some("doc_signed.odt"),
                Some("doc_signed.docx"),
            ]
        );
        assert_eq!(result.signed(), 7);
        assert!(
            result.results[4]
                .result
                .as_ref()
                .unwrap_err()
                .contains("contraseña")
        );

        let mut zip = Package::open(&result.zip).unwrap();
        for name in outputs.into_iter().flatten() {
            let signed = zip.read(name).unwrap();
            let data = name.ends_with(".csig").then(|| fixture("xades/doc.txt"));
            let verification = validation::verify(&signed, data.as_deref(), None).unwrap();
            assert!(verification.is_valid(), "{name}: {verification:?}");
        }
    }

    #[test]
    fn cosigns_and_countersigns() {
        let rsa = &load("rsa.p12")[0];
        let ec = &load("ec.p12")[0];
        let signed = sign_all(
            &[
                file("a.txt", fixture("xades/doc.txt")),
                file("b.xml", fixture("xades/doc.xml")),
                file("c.pdf", fixture("pades/doc.pdf")),
            ],
            rsa,
            &MassiveParams {
                cades_mode: SignatureMode::Implicit,
                ..MassiveParams::new(1_792_428_983)
            },
        )
        .unwrap();
        let mut zip = Package::open(&signed.zip).unwrap();
        let mut files: Vec<MassiveFile> = ["a.txt.csig", "b.xml.xsig", "c_signed.pdf"]
            .into_iter()
            .map(|name| file(name, zip.read(name).unwrap()))
            .collect();
        files.push(file("plain.txt", fixture("xades/doc.txt")));

        for operation in [
            MassiveOperation::Cosign,
            MassiveOperation::Countersign(CounterSignTarget::Leafs),
        ] {
            let result = sign_all(
                &files,
                ec,
                &MassiveParams {
                    operation,
                    ..MassiveParams::new(1_792_428_983)
                },
            )
            .unwrap();
            let mut zip = Package::open(&result.zip).unwrap();
            let suffix = match operation {
                MassiveOperation::Cosign => "_cosigned",
                _ => "_countersigned",
            };
            for (i, input) in ["a.txt.csig", "b.xml.xsig", "c_signed.pdf"]
                .into_iter()
                .enumerate()
            {
                if operation != MassiveOperation::Cosign && input.ends_with(".pdf") {
                    assert!(result.results[i].result.is_err());
                    continue;
                }
                let (stem, extension) = input.rsplit_once('.').unwrap();
                let expected = format!("{stem}{suffix}.{extension}");
                assert_eq!(result.results[i].result.as_deref(), Ok(expected.as_str()));
                let verification =
                    validation::verify(&zip.read(&expected).unwrap(), None, None).unwrap();
                assert!(
                    verification.is_valid(),
                    "{operation:?} {expected}: {verification:?}"
                );
            }
            // Not a signature.
            assert!(result.results[3].result.is_err());
        }
    }

    #[test]
    fn unique_names() {
        let names = vec![
            "a.csig".to_string(),
            "a (2).csig".to_string(),
            "b".to_string(),
        ];
        assert_eq!(unique_name(&names, "a.csig"), "a (3).csig");
        assert_eq!(unique_name(&names, "b"), "b (2)");
        assert_eq!(unique_name(&names, "c"), "c");
    }
}
