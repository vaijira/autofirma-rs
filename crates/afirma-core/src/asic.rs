//! ASiC-S containers (ETSI EN 319 162-1): a ZIP package with one data file and
//! its detached signature, CAdES (`META-INF/signature.p7s`) or XAdES
//! (`META-INF/signatures.xml`), as AutoFirma's `AOCAdESASiCSSigner` and
//! `AOXAdESASiCSSigner` make them.
//!
//! Unlike AutoFirma, which deflates it, the `mimetype` entry is stored first
//! and uncompressed, as the standard requires; both are read.

use std::io::{Cursor, Read, Write};

use serde::{Deserialize, Serialize};
use x509_cert::Certificate;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    algorithm::KeyType,
    cades::{self, CadesParams, PreparedSignature, SignatureMode},
    error::{Error, Result},
    format::mime_type,
    keystore::SigningKey,
    validation::Verification,
    xades::{self, PreparedXades, Profile, XadesParams},
};

/// MIME type of ASiC-S containers.
pub const MIME_TYPE: &str = "application/vnd.etsi.asic-s+zip";
const CADES_SIGNATURE: &str = "META-INF/signature.p7s";
const XADES_SIGNATURES: &str = "META-INF/signatures.xml";
/// Largest entry read from a container, to stop ZIP bombs.
const MAX_ENTRY_SIZE: u64 = 512 * 1024 * 1024;

/// Signature format inside the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsicFormat {
    /// CAdES detached signature (`CAdES-ASiC-S`).
    Cades,
    /// XAdES detached signature (`XAdES-ASiC-S`).
    Xades,
}

impl AsicFormat {
    fn signature_path(self) -> &'static str {
        match self {
            AsicFormat::Cades => CADES_SIGNATURE,
            AsicFormat::Xades => XADES_SIGNATURES,
        }
    }
}

/// Name AutoFirma gives the data file: `dataobject.` and the extension of its
/// MIME type.
pub fn default_file_name(data: &[u8]) -> String {
    let mime = mime_type(data);
    let extension = match mime.as_str() {
        "application/pdf" => "pdf",
        "text/xml" => "xml",
        "text/plain" => "txt",
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/tiff" => "tif",
        "application/zip" => "zip",
        "application/pkcs7-signature" => "p7s",
        "application/vnd.oasis.opendocument.text" => "odt",
        "application/vnd.oasis.opendocument.spreadsheet" => "ods",
        "application/vnd.oasis.opendocument.presentation" => "odp",
        _ => "bin",
    };
    format!("dataobject.{extension}")
}

/// Name of the data file inside the container: the last component of
/// `name`, or [`default_file_name`].
fn file_name(data: &[u8], name: Option<&str>) -> Result<String> {
    let name = name
        .and_then(|n| n.rsplit(['/', '\\']).next())
        .map(str::trim)
        .filter(|n| !n.is_empty());
    match name {
        None => Ok(default_file_name(data)),
        Some("mimetype") => Err(Error::InvalidAsic(
            "el fichero no puede llamarse «mimetype»".to_string(),
        )),
        Some(name) => Ok(name.to_string()),
    }
}

/// Builds the container.
fn package(file_name: &str, data: &[u8], format: AsicFormat, signature: &[u8]) -> Result<Vec<u8>> {
    let zip_error = |e: zip::result::ZipError| Error::InvalidAsic(e.to_string());
    let io_error = |e: std::io::Error| Error::InvalidAsic(e.to_string());
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(
        "mimetype",
        SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
    )
    .map_err(zip_error)?;
    zip.write_all(MIME_TYPE.as_bytes()).map_err(io_error)?;
    let deflated = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .large_file(data.len() as u64 >= u64::from(u32::MAX));
    zip.start_file(file_name, deflated).map_err(zip_error)?;
    zip.write_all(data).map_err(io_error)?;
    zip.start_file(format.signature_path(), deflated)
        .map_err(zip_error)?;
    zip.write_all(signature).map_err(io_error)?;
    Ok(zip.finish().map_err(zip_error)?.into_inner())
}

/// The signature inside a container being made.
#[derive(Debug, Clone)]
enum Inner {
    Cades(PreparedSignature),
    Xades(PreparedXades),
}

/// A container whose signature waits for the private key operation.
#[derive(Debug, Clone)]
pub struct PreparedAsic {
    file_name: String,
    data: Vec<u8>,
    inner: Inner,
}

impl PreparedAsic {
    /// Bytes the private key must sign.
    pub fn to_be_signed(&self) -> &[u8] {
        match &self.inner {
            Inner::Cades(prepared) => prepared.to_be_signed(),
            Inner::Xades(prepared) => prepared.to_be_signed(),
        }
    }

    /// Builds the container from the raw signature value.
    pub fn finish(self, signature: &[u8]) -> Result<Vec<u8>> {
        let (format, signature) = match self.inner {
            Inner::Cades(prepared) => (AsicFormat::Cades, prepared.finish(signature)?),
            Inner::Xades(prepared) => (AsicFormat::Xades, prepared.finish(signature)?),
        };
        package(&self.file_name, &self.data, format, &signature)
    }
}

/// First phase of a CAdES-ASiC-S signature. The CAdES signature is always
/// explicit (detached): `params.mode` is ignored.
pub fn prepare_cades(
    data: &[u8],
    name: Option<&str>,
    chain: &[Certificate],
    key_type: KeyType,
    params: &CadesParams,
) -> Result<PreparedAsic> {
    let params = CadesParams {
        mode: SignatureMode::Explicit,
        ..params.clone()
    };
    Ok(PreparedAsic {
        file_name: file_name(data, name)?,
        data: data.to_vec(),
        inner: Inner::Cades(cades::prepare(data, chain, key_type, &params)?),
    })
}

/// First phase of a XAdES-ASiC-S signature. `params.format` is ignored: the
/// signature references the data file of the container.
pub fn prepare_xades(
    data: &[u8],
    name: Option<&str>,
    chain: &[Certificate],
    key_type: KeyType,
    params: &XadesParams,
) -> Result<PreparedAsic> {
    let file_name = file_name(data, name)?;
    let prepared = xades::prepare_with(
        data,
        chain,
        key_type,
        params,
        Profile {
            asic_file: Some(&file_name),
            ..Profile::XADES
        },
    )?;
    Ok(PreparedAsic {
        file_name,
        data: data.to_vec(),
        inner: Inner::Xades(prepared),
    })
}

/// Signs `data` in a CAdES-ASiC-S container. `name` is the name of the data
/// file inside it ([`default_file_name`] when `None`).
pub fn sign_cades(
    data: &[u8],
    name: Option<&str>,
    key: &dyn SigningKey,
    params: &CadesParams,
) -> Result<Vec<u8>> {
    let prepared = prepare_cades(data, name, key.certificate_chain(), key.key_type(), params)?;
    let signature = key.sign_raw(params.digest, prepared.to_be_signed())?;
    prepared.finish(&signature)
}

/// Signs `data` in a XAdES-ASiC-S container; see [`sign_cades`].
pub fn sign_xades(
    data: &[u8],
    name: Option<&str>,
    key: &dyn SigningKey,
    params: &XadesParams,
) -> Result<Vec<u8>> {
    let prepared = prepare_xades(data, name, key.certificate_chain(), key.key_type(), params)?;
    let signature = key.sign_raw(params.digest, prepared.to_be_signed())?;
    prepared.finish(&signature)
}

/// Contents of an ASiC-S container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsicContainer {
    /// Name of the data file.
    pub file_name: String,
    /// The signed data.
    pub data: Vec<u8>,
    /// Format of the signature.
    pub format: AsicFormat,
    /// The signature file.
    pub signature: Vec<u8>,
}

impl AsicContainer {
    /// The container with another signature file (after adding timestamps).
    pub fn repackage(&self, signature: &[u8]) -> Result<Vec<u8>> {
        package(&self.file_name, &self.data, self.format, signature)
    }
}

fn read_entry<R: Read + std::io::Seek>(archive: &mut ZipArchive<R>, name: &str) -> Result<Vec<u8>> {
    let entry = archive
        .by_name(name)
        .map_err(|e| Error::InvalidAsic(format!("{name}: {e}")))?;
    let mut out = Vec::new();
    entry
        .take(MAX_ENTRY_SIZE + 1)
        .read_to_end(&mut out)
        .map_err(|e| Error::InvalidAsic(format!("{name}: {e}")))?;
    if out.len() as u64 > MAX_ENTRY_SIZE {
        return Err(Error::InvalidAsic(format!("{name} es demasiado grande")));
    }
    Ok(out)
}

/// Opens an ASiC-S container.
pub fn open(container: &[u8]) -> Result<AsicContainer> {
    let mut archive =
        ZipArchive::new(Cursor::new(container)).map_err(|e| Error::InvalidAsic(e.to_string()))?;
    let names: Vec<String> = archive.file_names().map(str::to_string).collect();
    if names.iter().any(|n| n == "mimetype") {
        let mime = read_entry(&mut archive, "mimetype")?;
        if mime.trim_ascii() != MIME_TYPE.as_bytes() {
            return Err(Error::InvalidAsic(format!(
                "tipo {} en lugar de {MIME_TYPE}",
                String::from_utf8_lossy(&mime)
            )));
        }
    }
    let format = if names.iter().any(|n| n == CADES_SIGNATURE) {
        AsicFormat::Cades
    } else if names.iter().any(|n| n == XADES_SIGNATURES) {
        AsicFormat::Xades
    } else {
        return Err(Error::InvalidAsic("no contiene ninguna firma".to_string()));
    };
    let data_files: Vec<&String> = names
        .iter()
        .filter(|n| *n != "mimetype" && !n.starts_with("META-INF/") && !n.ends_with('/'))
        .collect();
    let [file_name] = data_files[..] else {
        return Err(Error::InvalidAsic(format!(
            "un contenedor ASiC-S debe tener un único fichero de datos y tiene {}",
            data_files.len()
        )));
    };
    let file_name = file_name.clone();
    Ok(AsicContainer {
        data: read_entry(&mut archive, &file_name)?,
        signature: read_entry(&mut archive, format.signature_path())?,
        file_name,
        format,
    })
}

/// Whether `data` is an ASiC-S container.
pub fn is_asic(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04") && open(data).is_ok()
}

/// Result of verifying an ASiC-S container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsicReport {
    /// Name of the signed file.
    pub file_name: String,
    /// Verification of the signature inside.
    pub signature: Box<Verification>,
}

/// Verifies the signature of an ASiC-S container over its data file.
pub fn verify(container: &[u8]) -> Result<AsicReport> {
    let contents = open(container)?;
    let signature = match contents.format {
        AsicFormat::Cades => {
            Verification::Cades(cades::verify(&contents.signature, Some(&contents.data))?)
        }
        AsicFormat::Xades => {
            Verification::Xades(xades::verify(&contents.signature, Some(&contents.data))?)
        }
    };
    Ok(AsicReport {
        file_name: contents.file_name,
        signature: Box::new(signature),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{digest::DigestAlgorithm, keystore::tests::load};

    fn fixture(path: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/data/{path}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn verifies_autofirma_containers() {
        for name in ["autofirma-cades-rsa.asics", "autofirma-xades-rsa.asics"] {
            let report = verify(&fixture(&format!("asic/{name}"))).unwrap();
            assert_eq!(report.file_name, "dataobject.txt");
            assert!(report.signature.is_valid(), "{name}: {report:?}");
        }
    }

    #[test]
    fn sign_and_verify() {
        let data = fixture("xades/doc.txt");
        for keystore in ["rsa.p12", "ec.p12"] {
            let key = &load(keystore)[0];
            let cades = sign_cades(
                &data,
                Some("carpeta/informe final.txt"),
                key,
                &CadesParams {
                    digest: DigestAlgorithm::Sha256,
                    mode: SignatureMode::Implicit,
                    policy: None,
                    signing_time: 1_792_428_983,
                    content_description: None,
                },
            )
            .unwrap();
            let xades = sign_xades(&data, None, key, &XadesParams::new(1_792_428_983)).unwrap();
            for (container, format, name) in [
                (cades, AsicFormat::Cades, "informe final.txt"),
                (xades, AsicFormat::Xades, "dataobject.txt"),
            ] {
                // mimetype first and stored, as the standard requires.
                assert_eq!(&container[30..38], b"mimetype");
                assert_eq!(&container[38..38 + MIME_TYPE.len()], MIME_TYPE.as_bytes());
                assert!(is_asic(&container));
                let opened = open(&container).unwrap();
                assert_eq!(opened.format, format);
                assert_eq!(opened.file_name, name);
                assert_eq!(opened.data, data);
                let report = verify(&container).unwrap();
                assert!(
                    report.signature.is_valid(),
                    "{keystore} {format:?}: {report:?}"
                );
            }
        }
    }

    #[test]
    fn rejects_other_zips() {
        assert!(!is_asic(b"PK\x03\x04garbage"));
        let container = package("a.txt", b"x", AsicFormat::Cades, b"y").unwrap();
        let contents = open(&container).unwrap();
        assert_eq!(contents.signature, b"y");
        assert!(file_name(b"x", Some("mimetype")).is_err());
    }
}
