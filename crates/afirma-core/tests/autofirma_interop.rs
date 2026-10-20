//! Cross-validation of autofirma-rs signatures with AutoFirma's own validators
//! (`tools/AfirmaValidate.java`), `openssl cms -verify` (CAdES), poppler's
//! `pdfsig` and `qpdf --check` (PAdES), the JDK's XMLDSig (ODF, OOXML) and
//! LibreOffice (`tools/lo_verify.py`, ODF). Timestamps come from
//! `openssl ts -reply` acting as the TSA. AutoFirma's own signers co-sign and
//! counter-sign our signatures (`tools/AfirmaMulti.java`).
//!
//! Needs Java, OpenSSL, poppler-utils, qpdf, LibreOffice (with python3-uno)
//! and AutoFirma installed, so it is ignored by default:
//!
//! ```sh
//! cargo test -p afirma-core --test autofirma_interop -- --ignored
//! ```
//!
//! Set `AUTOFIRMA_JAR` if the jar is not at `/usr/lib/Autofirma/autofirma.jar`.

use std::{path::PathBuf, process::Command};

use afirma_core::{
    asic,
    cades::{self, CadesParams, SignatureMode},
    digest::DigestAlgorithm,
    format::SignatureFormat,
    keystore::load_pkcs12,
    multisign::CounterSignTarget,
    odf::{self, OdfParams},
    ooxml::{self, OoxmlParams},
    pades::{self, CertificationLevel, Font, PadesParams, Rect, SignaturePages, VisibleSignature},
    policy::PolicyPreset,
    tsp, validation,
    xades::{self, ProductionPlace, XadesFormat, XadesParams},
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

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
#[ignore]
fn autofirma_pdfsig_and_qpdf_accept_our_pdf_signatures() {
    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("autofirma_interop_pades");
    std::fs::create_dir_all(&out_dir).unwrap();
    let visible = |pages| VisibleSignature {
        pages,
        rect: Rect {
            llx: 72.0,
            lly: 72.0,
            urx: 272.0,
            ury: 142.0,
        },
        text: None,
        font: Font::default(),
        image: None,
        obfuscate: None,
        mask: None,
    };

    let mut failures = Vec::new();
    for keystore in ["rsa.p12", "ec.p12"] {
        let p12 = std::fs::read(repo().join("tests/data/certs").join(keystore)).unwrap();
        let key = &load_pkcs12(&p12, "1234").unwrap()[0];
        let base = PadesParams::new(now());
        let cases: Vec<(&str, &str, PadesParams)> = vec![
            ("doc.pdf", "bes", base.clone()),
            ("doc-xref.pdf", "xref-stream", base.clone()),
            (
                "doc.pdf",
                "age",
                PadesParams {
                    policy: Some(PolicyPreset::Age19.policy(SignatureFormat::Pades)),
                    reason: Some("Conformidad".to_string()),
                    location: Some("Madrid".to_string()),
                    ..base.clone()
                },
            ),
            (
                "doc-xref.pdf",
                "visible-all",
                PadesParams {
                    visible: Some(visible(SignaturePages::All)),
                    ..base.clone()
                },
            ),
            (
                "doc.pdf",
                "visible-append",
                PadesParams {
                    visible: Some(visible(SignaturePages::Append)),
                    ..base.clone()
                },
            ),
            (
                "doc.pdf",
                "certified",
                PadesParams {
                    certification: CertificationLevel::NoChanges,
                    visible: Some(visible(SignaturePages::Last)),
                    ..base.clone()
                },
            ),
            (
                "doc-aes256.pdf",
                "aes256",
                PadesParams {
                    password: Some("user".to_string()),
                    ..base.clone()
                },
            ),
            ("doc-rc4.pdf", "rc4", base.clone()),
        ];
        for (input, variant, params) in cases {
            let name = format!("{keystore}-{variant}.pdf");
            let pdf = std::fs::read(repo().join("tests/data/pades").join(input)).unwrap();
            let signed = pades::sign(&pdf, key, &params).unwrap();
            // A second signature on top, as co-signing a PDF does.
            let signed = if variant == "bes" {
                pades::sign(&signed, key, &base).unwrap()
            } else {
                signed
            };
            let path = out_dir.join(&name);
            std::fs::write(&path, &signed).unwrap();
            let password = params.password.as_deref();

            let mut java = Command::new("java");
            java.arg("-cp")
                .arg(autofirma_jar())
                .arg(repo().join("tools/AfirmaValidate.java"))
                .arg(&path);
            if let Some(password) = password {
                java.arg(password);
            }
            let (ok, output) = run(&mut java);
            if !ok {
                failures.push(format!("AutoFirma rejected {name}:\n{output}"));
            }

            let mut pdfsig = Command::new("pdfsig");
            if let Some(password) = password {
                pdfsig.args(["-upw", password]);
            }
            let (_, output) = run(pdfsig.arg(&path));
            let signatures = output.matches("Signature Field Name").count();
            let valid = output.matches("Signature is Valid.").count();
            if signatures == 0 || valid != signatures || !output.contains("Total document signed") {
                failures.push(format!("pdfsig rejected {name}:\n{output}"));
            }

            let mut qpdf = Command::new("qpdf");
            qpdf.arg("--check");
            if let Some(password) = password {
                qpdf.arg(format!("--password={password}"));
            }
            let (ok, output) = run(qpdf.arg(&path));
            if !ok || !output.contains("No syntax or stream encoding errors") {
                failures.push(format!("qpdf rejected {name}:\n{output}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore]
fn autofirma_accepts_our_xades_signatures() {
    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("autofirma_interop_xades");
    std::fs::create_dir_all(&out_dir).unwrap();
    let inputs = [
        (
            "xml",
            std::fs::read(repo().join("tests/data/xades/doc.xml")).unwrap(),
        ),
        ("bin", DATA.to_vec()),
    ];

    let mut failures = Vec::new();
    for keystore in ["rsa.p12", "ec.p12"] {
        let p12 = std::fs::read(repo().join("tests/data/certs").join(keystore)).unwrap();
        let key = &load_pkcs12(&p12, "1234").unwrap()[0];
        for format in [
            XadesFormat::Enveloping,
            XadesFormat::Enveloped,
            XadesFormat::Detached,
        ] {
            for (kind, data) in &inputs {
                if format == XadesFormat::Enveloped && *kind == "bin" {
                    continue;
                }
                for policy in [None, Some(PolicyPreset::Age19)] {
                    let params = XadesParams {
                        format,
                        policy: policy.map(|p| p.policy(SignatureFormat::Xades)),
                        utc_offset_minutes: 120,
                        production_place: ProductionPlace {
                            city: Some("Madrid".to_string()),
                            ..ProductionPlace::default()
                        },
                        claimed_roles: vec!["emisor".to_string()],
                        ..XadesParams::new(now())
                    };
                    let name = format!(
                        "{keystore}-{format:?}-{kind}-{}.xsig",
                        if policy.is_some() { "age" } else { "bes" }
                    );
                    let path = out_dir.join(&name);
                    std::fs::write(&path, xades::sign(data, key, &params).unwrap()).unwrap();

                    // AutoFirma 1.9's validator rejects binary XAdES Detached
                    // signatures, its own included (the JDK Base64 transform fails on
                    // the CONTENT element). Our verifier checks AutoFirma's reference
                    // (tests/data/xades/autofirma-binary-detached-rsa.xsig) instead.
                    if format == XadesFormat::Detached && *kind == "bin" {
                        continue;
                    }
                    let mut java = Command::new("java");
                    java.arg("-cp")
                        .arg(autofirma_jar())
                        .arg(repo().join("tools/AfirmaValidate.java"))
                        .arg(&path);
                    let (ok, output) = run(&mut java);
                    if !ok {
                        failures.push(format!("AutoFirma rejected {name}:\n{output}"));
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A TSA made with `openssl ts`: a self-signed certificate with the
/// critical `timeStamping` extended key usage.
struct OpensslTsa {
    dir: PathBuf,
}

impl OpensslTsa {
    fn new(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        let (ok, output) = run(Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
            ])
            .args(["-subj", "/C=ES/O=autofirma-rs/CN=autofirma-rs Test TSA"])
            .args(["-addext", "extendedKeyUsage=critical,timeStamping"])
            .arg("-keyout")
            .arg(dir.join("tsa.key"))
            .arg("-out")
            .arg(dir.join("tsa.pem")));
        assert!(ok, "{output}");
        std::fs::write(dir.join("serial"), "01\n").unwrap();
        std::fs::write(
            dir.join("tsa.cnf"),
            format!(
                "[ tsa ]\ndefault_tsa = tsa1\n[ tsa1 ]\nserial = {}\ncrypto_device = builtin\n\
                 signer_digest = sha256\ndefault_policy = 1.2.3.4.1\nother_policies = 0.4.0.2023.1.1\n\
                 digests = sha256, sha384, sha512\naccuracy = secs:1\nordering = no\ntsa_name = yes\n\
                 ess_cert_id_chain = no\ness_cert_id_alg = sha256\n",
                dir.join("serial").display()
            ),
        )
        .unwrap();
        OpensslTsa { dir }
    }

    fn respond(&self, request: &[u8]) -> Vec<u8> {
        let (query, reply) = (self.dir.join("query.tsq"), self.dir.join("reply.tsr"));
        std::fs::write(&query, request).unwrap();
        let (ok, output) = run(Command::new("openssl")
            .args(["ts", "-reply", "-config"])
            .arg(self.dir.join("tsa.cnf"))
            .arg("-queryfile")
            .arg(&query)
            .arg("-signer")
            .arg(self.dir.join("tsa.pem"))
            .arg("-inkey")
            .arg(self.dir.join("tsa.key"))
            .arg("-out")
            .arg(&reply));
        assert!(ok, "{output}");
        let (ok, output) = run(Command::new("openssl")
            .args(["ts", "-verify", "-queryfile"])
            .arg(&query)
            .arg("-in")
            .arg(&reply)
            .arg("-CAfile")
            .arg(self.dir.join("tsa.pem")));
        assert!(ok, "openssl does not accept our request: {output}");
        std::fs::read(&reply).unwrap()
    }

    /// Adds signature timestamps from this TSA to `signed`.
    fn stamp(&self, signed: &[u8]) -> Vec<u8> {
        let digest = DigestAlgorithm::Sha512;
        let responses: Vec<Vec<u8>> = tsp::signature_imprints(signed, digest)
            .unwrap()
            .iter()
            .map(|imprint| {
                self.respond(&tsp::request(digest, imprint, Some("0.4.0.2023.1.1")).unwrap())
            })
            .collect();
        assert!(!responses.is_empty());
        tsp::add_signature_timestamps(signed, digest, &responses).unwrap()
    }
}

#[test]
#[ignore]
fn timestamps_from_openssl_are_accepted() {
    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("autofirma_interop_tsp");
    let tsa = OpensslTsa::new(out_dir.join("tsa"));
    let p12 = std::fs::read(repo().join("tests/data/certs/rsa.p12")).unwrap();
    let key = &load_pkcs12(&p12, "1234").unwrap()[0];
    let xml = std::fs::read(repo().join("tests/data/xades/doc.xml")).unwrap();
    let pdf = std::fs::read(repo().join("tests/data/pades/doc.pdf")).unwrap();

    let cades_params = CadesParams {
        digest: DigestAlgorithm::Sha512,
        mode: SignatureMode::Explicit,
        policy: None,
        signing_time: now(),
        content_description: None,
    };
    let signed = [
        (
            "cades-t.csig",
            cades::sign(DATA, key, &cades_params).unwrap(),
        ),
        (
            "xades-t.xsig",
            xades::sign(
                &xml,
                key,
                &XadesParams {
                    format: XadesFormat::Enveloped,
                    utc_offset_minutes: 120,
                    ..XadesParams::new(now())
                },
            )
            .unwrap(),
        ),
        (
            "pades-t.pdf",
            pades::sign(
                &pdf,
                key,
                &PadesParams {
                    reserved_size: Some(32 * 1024),
                    ..PadesParams::new(now())
                },
            )
            .unwrap(),
        ),
    ];

    let data_path = out_dir.join("doc.txt");
    std::fs::write(&data_path, DATA).unwrap();
    let mut failures = Vec::new();
    for (name, signed) in signed {
        let mut stamped = tsa.stamp(&signed);
        if name.ends_with(".pdf") {
            // A document timestamp on top (PAdES-LTA style).
            let (prepared, imprint) =
                pades::prepare_document_timestamp(&stamped, None, DigestAlgorithm::Sha256).unwrap();
            let response =
                tsa.respond(&tsp::request(DigestAlgorithm::Sha256, &imprint, None).unwrap());
            stamped = pades::add_document_timestamp(&prepared, DigestAlgorithm::Sha256, &response)
                .unwrap();
        }
        let path = out_dir.join(name);
        std::fs::write(&path, &stamped).unwrap();

        let data = name.starts_with("cades").then_some(DATA);
        let verification = validation::verify(&stamped, data, None).unwrap();
        if !verification.is_valid()
            || !format!("{verification:?}").contains("timestamps: [TimestampReport")
        {
            failures.push(format!("we reject {name}: {verification:?}"));
        }

        let mut java = Command::new("java");
        java.arg("-cp")
            .arg(autofirma_jar())
            .arg(repo().join("tools/AfirmaValidate.java"))
            .arg(&path);
        if data.is_some() {
            java.arg(&data_path);
        }
        let (ok, output) = run(&mut java);
        if !ok {
            failures.push(format!("AutoFirma rejected {name}:\n{output}"));
        }

        if name.ends_with(".pdf") {
            // Poppler does not verify ETSI.RFC3161 document timestamps ("not yet
            // been verified"); the signature under it must stay valid.
            let (_, output) = run(Command::new("pdfsig").arg(&path));
            if output.matches("Signature is Valid.").count() != 1
                || output.contains("Signature is Invalid")
            {
                failures.push(format!("pdfsig rejected {name}:\n{output}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore]
fn autofirma_and_the_jdk_accept_our_asic_containers() {
    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("autofirma_interop_asic");
    let tsa = OpensslTsa::new(out_dir.join("tsa"));
    let mut failures = Vec::new();
    for keystore in ["rsa.p12", "ec.p12"] {
        let p12 = std::fs::read(repo().join("tests/data/certs").join(keystore)).unwrap();
        let key = &load_pkcs12(&p12, "1234").unwrap()[0];
        let cades_params = CadesParams {
            digest: DigestAlgorithm::Sha512,
            mode: SignatureMode::Explicit,
            policy: Some(PolicyPreset::Age19.policy(SignatureFormat::Cades)),
            signing_time: now(),
            content_description: None,
        };
        let containers = [
            (
                "cades",
                asic::sign_cades(DATA, Some("doc.txt"), key, &cades_params).unwrap(),
            ),
            (
                "xades",
                asic::sign_xades(DATA, None, key, &XadesParams::new(now())).unwrap(),
            ),
        ];
        for (format, container) in containers {
            for stamped in [false, true] {
                let container = if stamped {
                    tsa.stamp(&container)
                } else {
                    container.clone()
                };
                let name = format!(
                    "{keystore}-{format}{}.asics",
                    if stamped { "-t" } else { "" }
                );
                let path = out_dir.join(&name);
                std::fs::write(&path, &container).unwrap();
                let mut java = Command::new("java");
                java.arg("-cp")
                    .arg(autofirma_jar())
                    .arg(repo().join("tools/AfirmaValidate.java"))
                    .arg(&path);
                let (ok, output) = run(&mut java);
                if !ok {
                    failures.push(format!("{name} rejected:\n{output}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `java -cp autofirma.jar tools/<tool> args...`
fn java(tool: &str) -> Command {
    let mut java = Command::new("java");
    java.arg("-cp")
        .arg(autofirma_jar())
        .arg(repo().join("tools").join(tool));
    java
}

#[test]
#[ignore]
fn autofirma_accepts_our_cosignatures_and_countersignatures() {
    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("autofirma_interop_multi");
    std::fs::create_dir_all(&out_dir).unwrap();
    let data_path = out_dir.join("doc.txt");
    std::fs::write(&data_path, DATA).unwrap();
    let xml = std::fs::read(repo().join("tests/data/xades/doc.xml")).unwrap();
    let p12 = |name: &str| {
        let p12 = std::fs::read(repo().join("tests/data/certs").join(name)).unwrap();
        load_pkcs12(&p12, "1234").unwrap().remove(0)
    };
    let (rsa, ec) = (p12("rsa.p12"), p12("ec.p12"));
    let cades_params = |mode| CadesParams {
        digest: DigestAlgorithm::Sha512,
        mode,
        policy: Some(PolicyPreset::Age19.policy(SignatureFormat::Cades)),
        signing_time: now(),
        content_description: Some("Texto plano".to_string()),
    };
    let xades_params = |format| XadesParams {
        format,
        utc_offset_minutes: 120,
        ..XadesParams::new(now())
    };

    // Signed by RSA, co-signed by EC, then every signature counter-signed by RSA.
    let mut files: Vec<(String, Vec<u8>, bool)> = Vec::new();
    for mode in [SignatureMode::Explicit, SignatureMode::Implicit] {
        let signed = cades::sign(DATA, &rsa, &cades_params(mode)).unwrap();
        let cosigned = cades::cosign(&signed, None, &ec, &cades_params(mode)).unwrap();
        let tree = cades::countersign(
            &cosigned,
            CounterSignTarget::Tree,
            &rsa,
            &cades_params(mode),
        )
        .unwrap();
        let explicit = mode == SignatureMode::Explicit;
        files.push((format!("cades-{mode:?}-cosign.csig"), cosigned, explicit));
        files.push((format!("cades-{mode:?}-countersign.csig"), tree, explicit));
    }
    for format in [
        XadesFormat::Enveloping,
        XadesFormat::Enveloped,
        XadesFormat::Detached,
    ] {
        let signed = xades::sign(&xml, &rsa, &xades_params(format)).unwrap();
        let cosigned = xades::cosign(&signed, None, &ec, &xades_params(format)).unwrap();
        let tree = xades::countersign(
            &cosigned,
            CounterSignTarget::Tree,
            &rsa,
            &xades_params(format),
        )
        .unwrap();
        files.push((format!("xades-{format:?}-cosign.xsig"), cosigned, false));
        files.push((format!("xades-{format:?}-countersign.xsig"), tree, false));
    }

    let mut failures = Vec::new();
    for (name, signature, explicit) in &files {
        let path = out_dir.join(name);
        std::fs::write(&path, signature).unwrap();
        let data = explicit.then_some(DATA);
        let verification = validation::verify(signature, data, None).unwrap();
        if !verification.is_valid() {
            failures.push(format!("we reject {name}: {verification:?}"));
        }
        let mut validate = java("AfirmaValidate.java");
        validate.arg(&path);
        if *explicit {
            validate.arg(&data_path);
        }
        let (ok, output) = run(&mut validate);
        if !ok {
            failures.push(format!("AutoFirma rejected {name}:\n{output}"));
        }
        if name.starts_with("cades") {
            // OpenSSL checks every signer (not the counter-signatures).
            let mut openssl = Command::new("openssl");
            openssl
                .args(["cms", "-verify", "-binary", "-noverify", "-inform", "DER"])
                .arg("-in")
                .arg(&path)
                .arg("-out")
                .arg(out_dir.join("openssl.out"));
            if *explicit {
                openssl.arg("-content").arg(&data_path);
            }
            let (ok, output) = run(&mut openssl);
            if !ok {
                failures.push(format!("OpenSSL rejected {name}:\n{output}"));
            }
        }

        // AutoFirma adds its own signatures to ours, and we verify them.
        let format = if name.starts_with("cades") {
            "cades"
        } else {
            "xades"
        };
        for operation in ["cosign", "countersign-leafs"] {
            let out = out_dir.join(format!("{name}.autofirma-{operation}"));
            let mut multi = java("AfirmaMulti.java");
            multi
                .arg(repo().join("tests/data/certs/ec.p12"))
                .args([operation, format])
                .arg(&path)
                .arg(&out);
            if *explicit && operation == "cosign" {
                multi.arg(&data_path);
            }
            let (ok, output) = run(&mut multi);
            if !ok {
                failures.push(format!("AutoFirma could not {operation} {name}:\n{output}"));
                continue;
            }
            let theirs = std::fs::read(&out).unwrap();
            match validation::verify(&theirs, data, None) {
                Ok(verification) if verification.is_valid() => {}
                other => failures.push(format!(
                    "we reject AutoFirma's {operation} of {name}: {other:?}"
                )),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore]
fn the_jdk_and_libreoffice_accept_our_office_signatures() {
    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("autofirma_interop_office");
    std::fs::create_dir_all(&out_dir).unwrap();
    let p12 = |name: &str| {
        let p12 = std::fs::read(repo().join("tests/data/certs").join(name)).unwrap();
        load_pkcs12(&p12, "1234").unwrap().remove(0)
    };
    let (rsa, ec) = (p12("rsa.p12"), p12("ec.p12"));
    let odt = std::fs::read(repo().join("tests/data/odf/doc.odt")).unwrap();
    let docx = std::fs::read(repo().join("tests/data/ooxml/doc.docx")).unwrap();

    let mut documents = Vec::new();
    for digest in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha512] {
        let params = OdfParams {
            digest,
            utc_offset_minutes: 120,
            ..OdfParams::new(now())
        };
        let signed = odf::sign(&odt, &rsa, &params).unwrap();
        let cosigned = odf::sign(&signed, &ec, &params).unwrap();
        documents.push((format!("{digest:?}.odt"), cosigned));
        let params = OoxmlParams {
            digest,
            utc_offset_minutes: 120,
            comments: Some("Aprobado".to_string()),
            ..OoxmlParams::new(now())
        };
        let signed = ooxml::sign(&docx, &rsa, &params).unwrap();
        let cosigned = ooxml::sign(&signed, &ec, &params).unwrap();
        documents.push((format!("{digest:?}.docx"), cosigned));
    }

    let mut failures = Vec::new();
    let mut odf_paths = Vec::new();
    for (name, document) in &documents {
        let path = out_dir.join(name);
        std::fs::write(&path, document).unwrap();
        let (ok, output) = run(java("AfirmaValidate.java").arg(&path));
        if !ok {
            failures.push(format!("the JDK rejected {name}:\n{output}"));
        }
        if name.ends_with(".odt") {
            odf_paths.push(path.clone());
        }
        // AutoFirma signs our signed document again.
        let format = if name.ends_with(".odt") {
            "odf"
        } else {
            "ooxml"
        };
        let out = out_dir.join(format!("autofirma-{name}"));
        let (ok, output) = run(java("AfirmaMulti.java")
            .arg(repo().join("tests/data/certs/rsa.p12"))
            .args(["cosign", format])
            .arg(&path)
            .arg(&out));
        if !ok {
            failures.push(format!("AutoFirma could not sign {name}:\n{output}"));
            continue;
        }
        let theirs = std::fs::read(&out).unwrap();
        match validation::verify(&theirs, None, None) {
            Ok(verification) if verification.is_valid() => {}
            other => failures.push(format!(
                "we reject AutoFirma's signature of {name}: {other:?}"
            )),
        }
        if name.ends_with(".odt") {
            odf_paths.push(out);
        }
    }

    let (ok, output) = run(Command::new("python3")
        .arg(repo().join("tools/lo_verify.py"))
        .args(&odf_paths));
    if !ok {
        failures.push(format!(
            "LibreOffice rejected our ODF signatures:\n{output}"
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
