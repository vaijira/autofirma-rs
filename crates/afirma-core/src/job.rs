//! Jobs executed off the UI thread, in the Web Worker.
//!
//! The UI sends a [`Request`] to the worker and receives a [`Response`] with the
//! same `id`. Both are serialized with `serde-wasm-bindgen`; byte buffers use
//! `serde_bytes` so they travel as `Uint8Array` instead of arrays of numbers.
//!
//! Private keys never leave the worker: the [`Engine`] keeps them and the UI only
//! receives the certificate information and an id to refer to them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    cades::{self, CadesParams},
    cert::CertificateInfo,
    digest::{DigestAlgorithm, to_hex},
    error::{Error, Result},
    format::{DataKind, SignatureFormat},
    keystore::{SoftKey, load_pkcs12},
};

/// Message sent from the UI to the worker.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    /// Correlation id, echoed back in the [`Response`].
    pub id: u32,
    /// Work to do.
    pub job: Job,
}

/// Answer to a [`Request`].
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    /// Id of the [`Request`] this answers.
    pub id: u32,
    /// Job output, or an error message.
    pub result: std::result::Result<JobOutput, String>,
}

/// Message posted by the worker.
///
/// The worker installs its `onmessage` handler only after its Wasm module has been
/// instantiated; messages sent before that are lost. It therefore announces
/// [`WorkerEvent::Ready`] once, and the UI queues requests until then.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerEvent {
    /// The worker is ready to receive requests.
    Ready,
    /// Answer to a [`Request`].
    Response(Response),
}

/// Work the worker can do.
#[derive(Serialize, Deserialize)]
pub enum Job {
    /// Detect the kind of a file and compute its digest.
    Analyze {
        /// File contents.
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    /// Load the private keys of a PKCS#12 keystore.
    LoadPkcs12 {
        /// Keystore contents.
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// Keystore password. Zeroized after use.
        password: String,
    },
    /// Forget a loaded key, zeroizing it.
    RemoveKey {
        /// Key id.
        key_id: u32,
    },
    /// Create a CAdES signature.
    SignCades {
        /// Data to sign.
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// Key id.
        key_id: u32,
        /// Signature parameters.
        params: CadesParams,
    },
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print data or passwords.
        let name = match self {
            Job::Analyze { .. } => "Analyze",
            Job::LoadPkcs12 { .. } => "LoadPkcs12",
            Job::RemoveKey { .. } => "RemoveKey",
            Job::SignCades { .. } => "SignCades",
        };
        f.write_str(name)
    }
}

/// Result of a [`Job`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum JobOutput {
    /// Output of [`Job::Analyze`].
    Analysis(FileAnalysis),
    /// Output of [`Job::LoadPkcs12`]: the loaded keys.
    Keys(Vec<KeyEntry>),
    /// The job finished without output.
    Done,
    /// A signature.
    Signature(#[serde(with = "serde_bytes")] Vec<u8>),
}

/// Information about a loaded file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileAnalysis {
    /// File size in bytes.
    pub size: usize,
    /// Detected kind of data.
    pub kind: DataKind,
    /// Signature format AutoFirma would use by default.
    pub default_format: SignatureFormat,
    /// SHA-256 digest, hex encoded.
    pub sha256: String,
}

/// A private key loaded in the worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Id used to refer to the key in later jobs.
    pub id: u32,
    /// Alias (friendly name) in the keystore.
    pub alias: String,
    /// Signer certificate.
    pub certificate: CertificateInfo,
}

/// Runs jobs and keeps the loaded private keys.
#[derive(Debug, Default)]
pub struct Engine {
    keys: BTreeMap<u32, SoftKey>,
    next_key_id: u32,
}

impl Engine {
    /// Creates an engine without keys.
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles a [`Request`], turning errors into a message the UI can show.
    pub fn handle(&mut self, request: Request) -> Response {
        Response {
            id: request.id,
            result: self.run(request.job).map_err(|e| e.to_string()),
        }
    }

    /// Runs `job` and returns its output.
    pub fn run(&mut self, job: Job) -> Result<JobOutput> {
        match job {
            Job::Analyze { data } => analyze(&data).map(JobOutput::Analysis),
            Job::LoadPkcs12 { data, mut password } => {
                let keys = load_pkcs12(&data, &password);
                password.zeroize();
                let entries = keys?
                    .into_iter()
                    .map(|key| {
                        self.next_key_id += 1;
                        let entry = KeyEntry {
                            id: self.next_key_id,
                            alias: key.alias().to_string(),
                            certificate: key.certificate_info()?,
                        };
                        self.keys.insert(entry.id, key);
                        Ok(entry)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(JobOutput::Keys(entries))
            }
            Job::RemoveKey { key_id } => {
                self.keys.remove(&key_id).ok_or(Error::KeyNotFound)?;
                Ok(JobOutput::Done)
            }
            Job::SignCades {
                data,
                key_id,
                params,
            } => {
                let key = self.keys.get(&key_id).ok_or(Error::KeyNotFound)?;
                cades::sign(&data, key, &params).map(JobOutput::Signature)
            }
        }
    }
}

fn analyze(data: &[u8]) -> Result<FileAnalysis> {
    if data.is_empty() {
        return Err(Error::EmptyData);
    }
    let kind = DataKind::detect(data);
    Ok(FileAnalysis {
        size: data.len(),
        kind,
        default_format: kind.default_format(),
        sha256: to_hex(&DigestAlgorithm::Sha256.digest(data)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cades::SignatureMode;

    #[test]
    fn analyze_pdf() {
        let response = Engine::new().handle(Request {
            id: 7,
            job: Job::Analyze {
                data: b"%PDF-1.4\n%%EOF".to_vec(),
            },
        });
        assert_eq!(response.id, 7);
        let Ok(JobOutput::Analysis(analysis)) = response.result else {
            panic!("unexpected {:?}", response.result);
        };
        assert_eq!(analysis.kind, DataKind::Pdf);
        assert_eq!(analysis.default_format, SignatureFormat::Pades);
        assert_eq!(analysis.size, 14);
        assert_eq!(analysis.sha256.len(), 64);
    }

    #[test]
    fn analyze_empty_is_an_error() {
        let response = Engine::new().handle(Request {
            id: 1,
            job: Job::Analyze { data: vec![] },
        });
        assert!(response.result.is_err());
    }

    #[test]
    fn load_sign_and_remove_key() {
        let p12 = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/data/certs/rsa.p12"
        ))
        .unwrap();
        let mut engine = Engine::new();

        let wrong = engine.run(Job::LoadPkcs12 {
            data: p12.clone(),
            password: "nope".to_string(),
        });
        assert!(matches!(wrong, Err(Error::WrongPassword)));

        let Ok(JobOutput::Keys(keys)) = engine.run(Job::LoadPkcs12 {
            data: p12,
            password: "1234".to_string(),
        }) else {
            panic!("keystore not loaded");
        };
        assert_eq!(keys.len(), 1);
        let key_id = keys[0].id;

        let sign = |engine: &mut Engine| {
            engine.run(Job::SignCades {
                data: b"datos".to_vec(),
                key_id,
                params: CadesParams {
                    digest: DigestAlgorithm::Sha512,
                    mode: SignatureMode::Implicit,
                    policy: None,
                    signing_time: 1_792_065_600,
                    content_description: None,
                },
            })
        };
        let Ok(JobOutput::Signature(signature)) = sign(&mut engine) else {
            panic!("not signed");
        };
        assert!(cades::verify(&signature, None).unwrap().is_valid());

        assert_eq!(
            engine.run(Job::RemoveKey { key_id }).unwrap(),
            JobOutput::Done
        );
        assert!(matches!(sign(&mut engine), Err(Error::KeyNotFound)));
    }
}
