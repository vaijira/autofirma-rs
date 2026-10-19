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
    asic,
    cades::{self, CadesParams},
    cert::CertificateInfo,
    digest::{DigestAlgorithm, to_hex},
    error::{Error, Result},
    facturae::{self, FacturaeParams},
    format::{DataKind, SignatureFormat},
    keystore::{SigningKey, SoftKey, load_pkcs12},
    pades::{self, PadesParams, PdfInfo},
    triphase::{self, TriphaseData},
    tsp,
    validation::{self, Verification},
    xades::{self, XadesParams},
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
    /// Read the pages, encryption and signatures of a PDF.
    PdfInfo {
        /// PDF contents.
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// Password of an encrypted PDF.
        password: Option<String>,
    },
    /// Sign a PDF (PAdES).
    SignPades {
        /// PDF contents.
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// Key id.
        key_id: u32,
        /// Signature parameters.
        params: Box<PadesParams>,
    },
    /// Sign the pre-signatures of a triphase session.
    SignTriphase {
        /// Body of the server's response to the pre-sign request. Parsed here, so
        /// the UI does not need an XML parser.
        #[serde(with = "serde_bytes")]
        presign_response: Vec<u8>,
        /// Key id.
        key_id: u32,
        /// Digest algorithm.
        digest: DigestAlgorithm,
    },
    /// Create a XAdES signature.
    SignXades {
        /// Data to sign.
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// Key id.
        key_id: u32,
        /// Signature parameters.
        params: Box<XadesParams>,
    },
    /// Sign a FacturaE invoice.
    SignFacturae {
        /// The invoice.
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// Key id.
        key_id: u32,
        /// Signature parameters.
        params: FacturaeParams,
    },
    /// Sign data into an ASiC-S container.
    SignAsic {
        /// Data to sign.
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// Name of the data file in the container (`dataobject.<ext>` when `None`).
        file_name: Option<String>,
        /// Key id.
        key_id: u32,
        /// Signature inside the container.
        params: Box<AsicSignature>,
    },
    /// Build the timestamp requests for the signature timestamps of a signature
    /// (CAdES, XAdES, PDF or ASiC-S): one request body per signature to timestamp.
    TimestampRequests {
        /// The signature or signed document.
        #[serde(with = "serde_bytes")]
        signed: Vec<u8>,
        /// Digest algorithm of the imprints.
        digest: DigestAlgorithm,
        /// TSA policy OID.
        policy: Option<String>,
    },
    /// Add the tokens of the TSA responses to a signature.
    AddTimestamps {
        /// The signature or signed document.
        #[serde(with = "serde_bytes")]
        signed: Vec<u8>,
        /// Digest algorithm of the imprints.
        digest: DigestAlgorithm,
        /// TSA responses, one per request.
        responses: Vec<serde_bytes::ByteBuf>,
    },
    /// Append a document timestamp field to a PDF and build its timestamp request.
    PrepareDocumentTimestamp {
        /// PDF contents.
        #[serde(with = "serde_bytes")]
        pdf: Vec<u8>,
        /// Password of an encrypted PDF.
        password: Option<String>,
        /// Digest algorithm of the imprint.
        digest: DigestAlgorithm,
        /// TSA policy OID.
        policy: Option<String>,
    },
    /// Add the token of a TSA response to a PDF from [`Job::PrepareDocumentTimestamp`].
    AddDocumentTimestamp {
        /// The prepared PDF.
        #[serde(with = "serde_bytes")]
        prepared: Vec<u8>,
        /// Digest algorithm of the imprint.
        digest: DigestAlgorithm,
        /// TSA response.
        #[serde(with = "serde_bytes")]
        response: Vec<u8>,
    },
    /// Verify a signature (CAdES, XAdES, ASiC-S or PDF).
    Verify {
        /// Signature, or signed PDF.
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
        /// Signed data of an explicit (detached) CAdES or XAdES signature.
        #[serde(with = "serde_bytes", default)]
        data: Option<Vec<u8>>,
        /// Password of an encrypted PDF.
        password: Option<String>,
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
            Job::PdfInfo { .. } => "PdfInfo",
            Job::SignPades { .. } => "SignPades",
            Job::SignTriphase { .. } => "SignTriphase",
            Job::SignXades { .. } => "SignXades",
            Job::SignFacturae { .. } => "SignFacturae",
            Job::SignAsic { .. } => "SignAsic",
            Job::TimestampRequests { .. } => "TimestampRequests",
            Job::AddTimestamps { .. } => "AddTimestamps",
            Job::PrepareDocumentTimestamp { .. } => "PrepareDocumentTimestamp",
            Job::AddDocumentTimestamp { .. } => "AddDocumentTimestamp",
            Job::Verify { .. } => "Verify",
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
    /// A signature, or a signed document.
    Signature(#[serde(with = "serde_bytes")] Vec<u8>),
    /// Output of [`Job::PdfInfo`].
    PdfInfo(PdfInfo),
    /// Output of [`Job::SignTriphase`]: the session with the signatures.
    Triphase(TriphaseData),
    /// Output of [`Job::Verify`].
    Verification(Verification),
    /// Output of [`Job::TimestampRequests`]: the request bodies.
    TimestampRequests(Vec<serde_bytes::ByteBuf>),
    /// Output of [`Job::PrepareDocumentTimestamp`].
    DocumentTimestamp {
        /// The PDF with the empty timestamp field.
        #[serde(with = "serde_bytes")]
        prepared: Vec<u8>,
        /// Body of the timestamp request.
        #[serde(with = "serde_bytes")]
        request: Vec<u8>,
    },
}

/// Signature inside an ASiC-S container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AsicSignature {
    /// CAdES (always explicit).
    Cades(CadesParams),
    /// XAdES referencing the data file.
    Xades(XadesParams),
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
    /// Certificate chain (DER), leaf first. Needed for triphase signatures.
    pub chain: Vec<serde_bytes::ByteBuf>,
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
                            chain: key
                                .certificate_chain()
                                .iter()
                                .map(|cert| {
                                    crate::cert::to_der(cert).map(serde_bytes::ByteBuf::from)
                                })
                                .collect::<Result<_>>()?,
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
            Job::PdfInfo { data, password } => {
                pades::info(&data, password.as_deref()).map(JobOutput::PdfInfo)
            }
            Job::SignPades {
                data,
                key_id,
                params,
            } => {
                let key = self.keys.get(&key_id).ok_or(Error::KeyNotFound)?;
                pades::sign(&data, key, &params).map(JobOutput::Signature)
            }
            Job::SignTriphase {
                presign_response,
                key_id,
                digest,
            } => {
                let key = self.keys.get(&key_id).ok_or(Error::KeyNotFound)?;
                let mut session = triphase::parse_presign_response(&presign_response)?;
                session.sign(key, digest)?;
                Ok(JobOutput::Triphase(session))
            }
            Job::SignXades {
                data,
                key_id,
                params,
            } => {
                let key = self.keys.get(&key_id).ok_or(Error::KeyNotFound)?;
                xades::sign(&data, key, &params).map(JobOutput::Signature)
            }
            Job::SignFacturae {
                data,
                key_id,
                params,
            } => {
                let key = self.keys.get(&key_id).ok_or(Error::KeyNotFound)?;
                facturae::sign(&data, key, &params).map(JobOutput::Signature)
            }
            Job::SignAsic {
                data,
                file_name,
                key_id,
                params,
            } => {
                let key = self.keys.get(&key_id).ok_or(Error::KeyNotFound)?;
                match *params {
                    AsicSignature::Cades(params) => {
                        asic::sign_cades(&data, file_name.as_deref(), key, &params)
                    }
                    AsicSignature::Xades(params) => {
                        asic::sign_xades(&data, file_name.as_deref(), key, &params)
                    }
                }
                .map(JobOutput::Signature)
            }
            Job::TimestampRequests {
                signed,
                digest,
                policy,
            } => {
                let imprints = tsp::signature_imprints(&signed, digest)?;
                if imprints.is_empty() {
                    return Err(Error::Timestamp(
                        "la firma ya tiene sello de tiempo".to_string(),
                    ));
                }
                imprints
                    .iter()
                    .map(|imprint| {
                        tsp::request(digest, imprint, policy.as_deref())
                            .map(serde_bytes::ByteBuf::from)
                    })
                    .collect::<Result<_>>()
                    .map(JobOutput::TimestampRequests)
            }
            Job::AddTimestamps {
                signed,
                digest,
                responses,
            } => {
                let responses: Vec<Vec<u8>> = responses
                    .into_iter()
                    .map(serde_bytes::ByteBuf::into_vec)
                    .collect();
                tsp::add_signature_timestamps(&signed, digest, &responses).map(JobOutput::Signature)
            }
            Job::PrepareDocumentTimestamp {
                pdf,
                password,
                digest,
                policy,
            } => {
                let (prepared, imprint) =
                    pades::prepare_document_timestamp(&pdf, password.as_deref(), digest)?;
                Ok(JobOutput::DocumentTimestamp {
                    prepared,
                    request: tsp::request(digest, &imprint, policy.as_deref())?,
                })
            }
            Job::AddDocumentTimestamp {
                prepared,
                digest,
                response,
            } => pades::add_document_timestamp(&prepared, digest, &response)
                .map(JobOutput::Signature),
            Job::Verify {
                signature,
                data,
                password,
            } => validation::verify(&signature, data.as_deref(), password.as_deref())
                .map(JobOutput::Verification),
        }
    }
}

fn analyze(data: &[u8]) -> Result<FileAnalysis> {
    if data.is_empty() {
        return Err(Error::EmptyData);
    }
    let kind = DataKind::detect(data);
    let default_format = if kind == DataKind::Xml && facturae::is_facturae(data) {
        SignatureFormat::Facturae
    } else {
        kind.default_format()
    };
    Ok(FileAnalysis {
        size: data.len(),
        kind,
        default_format,
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

    #[test]
    fn pdf_jobs() {
        let read = |path: &str| {
            std::fs::read(format!(
                "{}/../../tests/data/{path}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap()
        };
        let mut engine = Engine::new();
        let Ok(JobOutput::Keys(keys)) = engine.run(Job::LoadPkcs12 {
            data: read("certs/ec.p12"),
            password: "1234".to_string(),
        }) else {
            panic!("keystore not loaded");
        };
        assert_eq!(keys[0].chain.len(), 2);

        let pdf = read("pades/doc-aes256.pdf");
        assert!(matches!(
            engine.run(Job::PdfInfo {
                data: pdf.clone(),
                password: None
            }),
            Err(Error::PdfPasswordRequired)
        ));
        let Ok(JobOutput::PdfInfo(info)) = engine.run(Job::PdfInfo {
            data: pdf.clone(),
            password: Some("user".to_string()),
        }) else {
            panic!("no info");
        };
        assert_eq!(info.pages.len(), 1);

        let Ok(JobOutput::Signature(signed)) = engine.run(Job::SignPades {
            data: pdf,
            key_id: keys[0].id,
            params: Box::new(PadesParams {
                password: Some("user".to_string()),
                ..PadesParams::new(1_792_159_674)
            }),
        }) else {
            panic!("not signed");
        };
        let Ok(JobOutput::Verification(verification)) = engine.run(Job::Verify {
            signature: signed,
            data: None,
            password: Some("user".to_string()),
        }) else {
            panic!("not verified");
        };
        assert!(verification.is_valid());
    }

    #[test]
    fn xml_asic_and_timestamp_jobs() {
        let read = |path: &str| {
            std::fs::read(format!(
                "{}/../../tests/data/{path}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap()
        };
        let mut engine = Engine::new();
        let Ok(JobOutput::Keys(keys)) = engine.run(Job::LoadPkcs12 {
            data: read("certs/rsa.p12"),
            password: "1234".to_string(),
        }) else {
            panic!("keystore not loaded");
        };
        let key_id = keys[0].id;

        let Ok(JobOutput::Analysis(analysis)) = engine.run(Job::Analyze {
            data: read("xades/factura.xml"),
        }) else {
            panic!("not analyzed");
        };
        assert_eq!(analysis.default_format, SignatureFormat::Facturae);

        let time = 1_792_428_983;
        let signatures = [
            engine.run(Job::SignXades {
                data: read("xades/doc.xml"),
                key_id,
                params: Box::new(XadesParams::new(time)),
            }),
            engine.run(Job::SignFacturae {
                data: read("xades/factura.xml"),
                key_id,
                params: FacturaeParams::new(time),
            }),
            engine.run(Job::SignAsic {
                data: read("xades/doc.txt"),
                file_name: None,
                key_id,
                params: Box::new(AsicSignature::Xades(XadesParams::new(time))),
            }),
        ];
        for signature in signatures {
            let Ok(JobOutput::Signature(signed)) = signature else {
                panic!("not signed: {signature:?}");
            };
            let Ok(JobOutput::TimestampRequests(requests)) = engine.run(Job::TimestampRequests {
                signed: signed.clone(),
                digest: DigestAlgorithm::Sha256,
                policy: None,
            }) else {
                panic!("no requests");
            };
            let responses = requests
                .iter()
                .map(|request| {
                    serde_bytes::ByteBuf::from(tsp::tests::tsa_response(request, "20261019165624Z"))
                })
                .collect();
            let Ok(JobOutput::Signature(stamped)) = engine.run(Job::AddTimestamps {
                signed,
                digest: DigestAlgorithm::Sha256,
                responses,
            }) else {
                panic!("not stamped");
            };
            let Ok(JobOutput::Verification(verification)) = engine.run(Job::Verify {
                signature: stamped,
                data: None,
                password: None,
            }) else {
                panic!("not verified");
            };
            assert!(verification.is_valid(), "{verification:?}");
        }
    }
}
