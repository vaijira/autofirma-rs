//! Jobs executed off the UI thread, in the Web Worker.
//!
//! The UI sends a [`Request`] to the worker and receives a [`Response`] with the
//! same `id`. Both are serialized with `serde-wasm-bindgen`; byte buffers use
//! `serde_bytes` so they travel as `Uint8Array` instead of arrays of numbers.

use serde::{Deserialize, Serialize};

use crate::{
    digest::{DigestAlgorithm, to_hex},
    error::{Error, Result},
    format::{DataKind, SignatureFormat},
};

/// Message sent from the UI to the worker.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    /// Correlation id, echoed back in the [`Response`].
    pub id: u32,
    /// Work to do.
    pub job: Job,
}

/// Message sent from the worker back to the UI.
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
#[derive(Debug, Serialize, Deserialize)]
pub enum Job {
    /// Detect the kind of a file and compute its digest.
    Analyze {
        /// File contents.
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
}

/// Result of a [`Job`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum JobOutput {
    /// Output of [`Job::Analyze`].
    Analysis(FileAnalysis),
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

/// Runs `job` and returns its output.
pub fn run(job: Job) -> Result<JobOutput> {
    match job {
        Job::Analyze { data } => analyze(&data).map(JobOutput::Analysis),
    }
}

/// Handles a [`Request`], turning errors into a message the UI can show.
pub fn handle(request: Request) -> Response {
    Response {
        id: request.id,
        result: run(request.job).map_err(|e| e.to_string()),
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

    #[test]
    fn analyze_pdf() {
        let response = handle(Request {
            id: 7,
            job: Job::Analyze {
                data: b"%PDF-1.4\n%%EOF".to_vec(),
            },
        });
        assert_eq!(response.id, 7);
        let JobOutput::Analysis(analysis) = response.result.unwrap();
        assert_eq!(analysis.kind, DataKind::Pdf);
        assert_eq!(analysis.default_format, SignatureFormat::Pades);
        assert_eq!(analysis.size, 14);
        assert_eq!(analysis.sha256.len(), 64);
    }

    #[test]
    fn analyze_empty_is_an_error() {
        let response = handle(Request {
            id: 1,
            job: Job::Analyze { data: vec![] },
        });
        assert!(response.result.is_err());
    }
}
