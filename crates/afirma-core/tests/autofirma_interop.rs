//! Cross-validation of autofirma-rs CAdES signatures with AutoFirma's own
//! validator (`tools/AfirmaValidate.java`) and `openssl cms -verify`.
//!
//! Needs Java, OpenSSL and AutoFirma installed, so it is ignored by default:
//!
//! ```sh
//! cargo test -p afirma-core --test autofirma_interop -- --ignored
//! ```
//!
//! Set `AUTOFIRMA_JAR` if the jar is not at `/usr/lib/Autofirma/autofirma.jar`.

use std::{path::PathBuf, process::Command};

use afirma_core::{
    cades::{self, CadesParams, SignatureMode},
    digest::DigestAlgorithm,
    format::SignatureFormat,
    keystore::load_pkcs12,
    policy::PolicyPreset,
};

const DATA: &[u8] = b"Hola autofirma-rs\n";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn autofirma_jar() -> String {
    std::env::var("AUTOFIRMA_JAR").unwrap_or_else(|_| "/usr/lib/Autofirma/autofirma.jar".into())
}

fn run(command: &mut Command) -> (bool, String) {
    let output = command.output().expect("command not found");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

#[test]
#[ignore]
fn autofirma_and_openssl_accept_our_signatures() {
    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("autofirma_interop");
    std::fs::create_dir_all(&out_dir).unwrap();
    let data_path = out_dir.join("doc.txt");
    std::fs::write(&data_path, DATA).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut failures = Vec::new();
    for keystore in ["rsa.p12", "ec.p12"] {
        let p12 = std::fs::read(repo().join("tests/data/certs").join(keystore)).unwrap();
        let key = &load_pkcs12(&p12, "1234").unwrap()[0];

        for digest in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha512] {
            for mode in [SignatureMode::Explicit, SignatureMode::Implicit] {
                for policy in [None, Some(PolicyPreset::Age19)] {
                    let params = CadesParams {
                        digest,
                        mode,
                        policy: policy.map(|p| p.policy(SignatureFormat::Cades)),
                        // AutoFirma checks the certificate validity at the signing time.
                        signing_time: now,
                        content_description: Some("Texto plano".to_string()),
                    };
                    let name = format!(
                        "{keystore}-{digest:?}-{mode:?}-{}.csig",
                        if policy.is_some() { "age" } else { "bes" }
                    );
                    let sig_path = out_dir.join(&name);
                    std::fs::write(&sig_path, cades::sign(DATA, key, &params).unwrap()).unwrap();

                    let mut java = Command::new("java");
                    java.arg("-cp")
                        .arg(autofirma_jar())
                        .arg(repo().join("tools/AfirmaValidate.java"))
                        .arg(&sig_path);
                    if mode == SignatureMode::Explicit {
                        java.arg(&data_path);
                    }
                    let (ok, output) = run(&mut java);
                    if !ok {
                        failures.push(format!("AutoFirma rejected {name}:\n{output}"));
                    }

                    // -noverify: our test CA is not a trusted root.
                    let mut openssl = Command::new("openssl");
                    openssl
                        .args(["cms", "-verify", "-binary", "-noverify", "-inform", "DER"])
                        .arg("-in")
                        .arg(&sig_path)
                        .arg("-out")
                        .arg(out_dir.join("openssl.out"));
                    if mode == SignatureMode::Explicit {
                        openssl.arg("-content").arg(&data_path);
                    }
                    let (ok, output) = run(&mut openssl);
                    if !ok {
                        failures.push(format!("OpenSSL rejected {name}:\n{output}"));
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
