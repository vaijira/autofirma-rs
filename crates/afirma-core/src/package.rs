//! ZIP packages of ODF and OOXML documents: reading their parts and writing
//! them back with some parts changed or added. Parts that do not change are
//! copied as they are, compressed bytes included.

use std::io::{Cursor, Read, Write};

use serde::{Deserialize, Serialize};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    error::{Error, Result},
    xades::XadesVerifyReport,
};

/// Result of verifying the signatures of an ODF or OOXML document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageReport {
    /// Verification of every signature.
    pub signatures: XadesVerifyReport,
    /// Parts of the document that some signature does not cover (added after
    /// signing, or left out by the signer).
    pub unsigned_parts: Vec<String>,
}

impl PackageReport {
    /// Whether every signature is valid and covers the whole document.
    pub fn is_valid(&self) -> bool {
        self.signatures.is_valid() && self.unsigned_parts.is_empty()
    }
}

/// Largest part read from a package, to stop ZIP bombs.
const MAX_PART_SIZE: u64 = 512 * 1024 * 1024;

fn zip_error(e: zip::result::ZipError) -> Error {
    Error::InvalidPackage(e.to_string())
}

fn io_error(e: std::io::Error) -> Error {
    Error::InvalidPackage(e.to_string())
}

/// An opened ZIP package.
pub(crate) struct Package<'a> {
    archive: ZipArchive<Cursor<&'a [u8]>>,
    /// Names of the parts (not directories), in archive order.
    names: Vec<String>,
}

impl std::fmt::Debug for Package<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Package")
            .field("names", &self.names)
            .finish()
    }
}

impl<'a> Package<'a> {
    pub fn open(data: &'a [u8]) -> Result<Self> {
        let mut archive = ZipArchive::new(Cursor::new(data)).map_err(zip_error)?;
        let mut names = Vec::with_capacity(archive.len());
        for i in 0..archive.len() {
            let entry = archive.by_index_raw(i).map_err(zip_error)?;
            if !entry.is_dir() {
                names.push(entry.name().to_string());
            }
        }
        Ok(Package { archive, names })
    }

    /// Names of the parts, in archive order.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Whether the package has a part named `name`.
    pub fn has(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }

    /// Contents of the part `name`.
    pub fn read(&mut self, name: &str) -> Result<Vec<u8>> {
        let entry = self
            .archive
            .by_name(name)
            .map_err(|e| Error::InvalidPackage(format!("{name}: {e}")))?;
        let mut out = Vec::new();
        entry
            .take(MAX_PART_SIZE + 1)
            .read_to_end(&mut out)
            .map_err(|e| Error::InvalidPackage(format!("{name}: {e}")))?;
        if out.len() as u64 > MAX_PART_SIZE {
            return Err(Error::InvalidPackage(format!("{name} es demasiado grande")));
        }
        Ok(out)
    }

    /// The package with the parts of `changes` replaced (in place) or added (at
    /// the end, in order). The other parts are copied unchanged.
    pub fn rewrite(&mut self, changes: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        let mut written = vec![false; changes.len()];
        for i in 0..self.archive.len() {
            let entry = self.archive.by_index_raw(i).map_err(zip_error)?;
            match changes.iter().position(|(name, _)| name == entry.name()) {
                Some(change) => {
                    let name = entry.name().to_string();
                    drop(entry);
                    write_part(&mut zip, &name, &changes[change].1)?;
                    written[change] = true;
                }
                None => zip.raw_copy_file(entry).map_err(zip_error)?,
            }
        }
        for ((name, content), written) in changes.iter().zip(written) {
            if !written {
                write_part(&mut zip, name, content)?;
            }
        }
        Ok(zip.finish().map_err(zip_error)?.into_inner())
    }
}

fn write_part(zip: &mut ZipWriter<Cursor<Vec<u8>>>, name: &str, content: &[u8]) -> Result<()> {
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .large_file(content.len() as u64 >= u64::from(u32::MAX));
    zip.start_file(name, options).map_err(zip_error)?;
    zip.write_all(content).map_err(io_error)
}

/// Decodes `%XX` escapes of a URI path (part names in references).
pub(crate) fn percent_decode(uri: &str) -> String {
    let bytes = uri.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        match (
            bytes[i],
            bytes.get(i + 1).copied(),
            bytes.get(i + 2).copied(),
        ) {
            (b'%', Some(h), Some(l)) if hex(h).is_some() && hex(l).is_some() => {
                out.push((hex(h).unwrap() * 16 + hex(l).unwrap()) as u8);
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A package with the given parts; the first one is stored uncompressed.
    pub fn zip(parts: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for (i, (name, content)) in parts.iter().enumerate() {
            let method = if i == 0 {
                CompressionMethod::Stored
            } else {
                CompressionMethod::Deflated
            };
            zip.start_file(
                *name,
                SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
            zip.write_all(content).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn rewrites_keeping_the_other_parts() {
        let original = zip(&[("mimetype", b"x/y"), ("a.xml", b"<a/>"), ("b", b"bb")]);
        let mut package = Package::open(&original).unwrap();
        assert_eq!(package.names(), ["mimetype", "a.xml", "b"]);
        let rewritten = package
            .rewrite(&[
                ("a.xml".to_string(), b"<a>1</a>".to_vec()),
                ("c/d".to_string(), b"d".to_vec()),
            ])
            .unwrap();
        // The first part is still stored first.
        assert_eq!(&rewritten[30..38], b"mimetype");
        let mut package = Package::open(&rewritten).unwrap();
        assert_eq!(package.names(), ["mimetype", "a.xml", "b", "c/d"]);
        assert_eq!(package.read("a.xml").unwrap(), b"<a>1</a>");
        assert_eq!(package.read("b").unwrap(), b"bb");
        assert!(package.read("zz").is_err());
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(
            percent_decode("Pictures/a%20b%C3%B1.png"),
            "Pictures/a bñ.png"
        );
        assert_eq!(percent_decode("100%"), "100%");
    }
}
