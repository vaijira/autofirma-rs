//! Triphase signing against the pre/post processors of clienteafirma's
//! `afirma-server-triphase-signer`, served by `tools/triphase-server/run.sh`.
//!
//! Needs that server running, so it is ignored by default:
//!
//! ```sh
//! tools/triphase-server/run.sh &
//! cargo test -p afirma-core --test triphase_interop -- --ignored
//! ```
//!
//! Set `TRIPHASE_URL` to use another server.

use std::{
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
};

use afirma_core::{
    digest::DigestAlgorithm,
    keystore::{SigningKey, load_pkcs12},
    pades::{Font, PadesParams, Rect, SignaturePages, VisibleSignature},
    params::ExtraParams,
    triphase::{
        self, CryptoOperation, TriphaseFormat, TriphaseRequest, parse_postsign_response,
        parse_presign_response,
    },
    validation::{self, Verification},
};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn server_url() -> String {
    std::env::var("TRIPHASE_URL").unwrap_or_else(|_| {
        "http://127.0.0.1:8090/afirma-server-triphase-signer/SignatureService".to_string()
    })
}

/// Minimal blocking HTTP/1.1 POST.
fn post(url: &str, body: &str) -> Vec<u8> {
    let rest = url.strip_prefix("http://").expect("only http:// URLs");
    let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let mut stream = TcpStream::connect(host).expect("triphase server not running");
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP response")
        + 4;
    let head = String::from_utf8_lossy(&response[..start]).to_lowercase();
    let body = response[start..].to_vec();
    if head.contains("transfer-encoding: chunked") {
        dechunk(&body)
    } else {
        body
    }
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n").unwrap();
        let size =
            usize::from_str_radix(String::from_utf8_lossy(&body[..line_end]).trim(), 16).unwrap();
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&body[line_end + 2..line_end + 2 + size]);
        body = &body[line_end + 2 + size + 2..];
    }
}

fn triphase_sign(
    key: &dyn SigningKey,
    format: TriphaseFormat,
    document: &[u8],
    params: ExtraParams,
) -> Vec<u8> {
    let request = TriphaseRequest {
        format,
        operation: CryptoOperation::Sign,
        digest: DigestAlgorithm::Sha512,
        key_type: key.key_type(),
        chain: key
            .certificate_chain()
            .iter()
            .map(|c| der::Encode::to_der(c).unwrap())
            .collect(),
        document_id: triphase::document_id(document),
        params,
    };
    let mut session =
        parse_presign_response(&post(&server_url(), &request.presign_body())).unwrap();
    session.sign(key, request.digest).unwrap();
    parse_postsign_response(&post(&server_url(), &request.postsign_body(&session))).unwrap()
}

#[test]
#[ignore]
fn signs_with_the_autofirma_triphase_server() {
    let pdf = std::fs::read(repo().join("tests/data/pades/doc.pdf")).unwrap();
    for keystore in ["rsa.p12", "ec.p12"] {
        let p12 = std::fs::read(repo().join("tests/data/certs").join(keystore)).unwrap();
        let key = &load_pkcs12(&p12, "1234").unwrap()[0];

        // PAdES, visible, with our options translated to AutoFirma's extraParams.
        let params = PadesParams {
            reason: Some("Prueba trifásica".to_string()),
            visible: Some(VisibleSignature {
                pages: SignaturePages::Last,
                rect: Rect {
                    llx: 72.0,
                    lly: 72.0,
                    urx: 272.0,
                    ury: 142.0,
                },
                text: Some("Firmado por $$SUBJECTCN$$".to_string()),
                font: Font::default(),
                image: None,
                obfuscate: None,
                mask: None,
            }),
            ..PadesParams::new(0)
        };
        let signed = triphase_sign(key, TriphaseFormat::Pades, &pdf, ExtraParams::from(&params));
        let Verification::Pades(report) = validation::verify(&signed, None, None).unwrap() else {
            panic!("not a PDF");
        };
        assert!(report.is_valid(), "{keystore}: {report:?}");
        assert_eq!(
            report.signatures[0].reason.as_deref(),
            Some("Prueba trifásica")
        );

        // CAdES, implicit.
        let mut params = ExtraParams::default();
        params.set("mode", "implicit");
        let signature = triphase_sign(key, TriphaseFormat::Cades, b"Hola triphase\n", params);
        let verification = validation::verify(&signature, None, None).unwrap();
        assert!(verification.is_valid(), "{keystore}: {verification:?}");
    }
}
