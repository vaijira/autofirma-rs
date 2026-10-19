use super::*;
use crate::{
    cades::SignerStatus, format::SignatureFormat, keystore::tests::load, policy::PolicyPreset,
    tsp::tests::tsa_response,
};

// 2026-10-19T16:56:23Z
const SIGNING_TIME: i64 = 1_792_428_983;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/data/xades/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The text between `start` and `end` (both included), first occurrence.
fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let from = text.find(start).unwrap_or_else(|| panic!("no {start}"));
    let to = from + text[from..].find(end).unwrap_or_else(|| panic!("no {end}")) + end.len();
    &text[from..to]
}

#[test]
fn verifies_autofirma_signatures() {
    for (name, policy) in [
        ("autofirma-enveloping-rsa.xsig", None),
        ("autofirma-enveloped-rsa.xsig", None),
        ("autofirma-detached-rsa.xsig", None),
        ("autofirma-binary-enveloping-rsa.xsig", None),
        ("autofirma-binary-detached-rsa.xsig", None),
        ("autofirma-enveloped-ec.xsig", None),
        (
            "autofirma-enveloped-age-rsa.xsig",
            Some("2.16.724.1.3.1.1.2.1.9"),
        ),
        (
            "autofirma-facturae-rsa.xsig",
            Some(
                "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
            ),
        ),
    ] {
        let report = verify(&fixture(name), None).unwrap();
        assert!(report.is_valid(), "{name}: {report:?}");
        let signature = &report.signatures[0];
        assert!(signature.xades, "{name}");
        assert_eq!(signature.signer.digest, Some(DigestAlgorithm::Sha512));
        assert!(signature.signer.certificate.is_some());
        assert!(signature.signer.signing_time.is_some());
        assert_eq!(signature.signer.policy.as_deref(), policy, "{name}");
    }
    let report = verify(&fixture("autofirma-enveloped-age-rsa.xsig"), None).unwrap();
    assert_eq!(report.signatures[0].claimed_roles, ["emisor"]);
    assert_eq!(
        report.signatures[0].production_city.as_deref(),
        Some("Madrid")
    );
}

fn params(format: XadesFormat, digest: DigestAlgorithm, policy: bool) -> XadesParams {
    XadesParams {
        digest,
        format,
        policy: policy.then(|| PolicyPreset::Age19.policy(SignatureFormat::Xades)),
        utc_offset_minutes: 120,
        production_place: ProductionPlace {
            city: Some("Alcalá de Henares".to_string()),
            ..ProductionPlace::default()
        },
        claimed_roles: vec!["emisor".to_string()],
        ..XadesParams::new(SIGNING_TIME)
    }
}

#[test]
fn sign_and_verify_every_combination() {
    let xml = fixture("doc.xml");
    let binary = fixture("doc.txt");
    for keystore in ["rsa.p12", "ec.p12"] {
        let key = &load(keystore)[0];
        for format in [
            XadesFormat::Enveloping,
            XadesFormat::Enveloped,
            XadesFormat::Detached,
        ] {
            for digest in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha512] {
                for policy in [false, true] {
                    for data in [&xml, &binary] {
                        let params = params(format, digest, policy);
                        let result = sign(data, key, &params);
                        if format == XadesFormat::Enveloped && data == &binary {
                            assert!(matches!(result, Err(Error::Unsupported(_))));
                            continue;
                        }
                        let signed = result.unwrap();
                        let report = verify(&signed, None).unwrap();
                        let case = format!("{keystore} {format:?} {digest:?} {policy}");
                        assert!(report.is_valid(), "{case}: {report:?}");
                        let signer = &report.signatures[0].signer;
                        assert_eq!(signer.digest, Some(digest));
                        assert_eq!(signer.signing_time, Some(SIGNING_TIME));
                        assert_eq!(
                            signer.policy.as_deref(),
                            policy.then_some("2.16.724.1.3.1.1.2.1.9")
                        );
                        assert_eq!(
                            report.signatures[0].production_city.as_deref(),
                            Some("Alcalá de Henares")
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn structure_matches_autofirma() {
    let key = &load("rsa.p12")[0];
    let ours = text(
        &sign(
            &fixture("doc.xml"),
            key,
            &params(XadesFormat::Enveloped, DigestAlgorithm::Sha512, true),
        )
        .unwrap(),
    );
    let theirs = text(&fixture("autofirma-enveloped-age-rsa.xsig"));

    // Same transforms on the enveloped reference.
    assert_eq!(
        between(&ours, "<ds:Transforms>", "</ds:Transforms>"),
        between(&theirs, "<ds:Transforms>", "</ds:Transforms>")
    );
    // Same certificates and public key, byte for byte.
    assert_eq!(
        between(&ours, "<ds:X509Data>", "</ds:KeyValue>"),
        between(&theirs, "<ds:X509Data>", "</ds:KeyValue>")
    );
    // Same signing certificate and policy.
    assert_eq!(
        between(
            &ours,
            "<xades:SigningCertificate>",
            "</xades:SignaturePolicyIdentifier>"
        ),
        between(
            &theirs,
            "<xades:SigningCertificate>",
            "</xades:SignaturePolicyIdentifier>"
        )
    );
    assert!(ours.contains("<xades:SigningTime>2026-10-19T18:56:23+02:00</xades:SigningTime>"));
    // Same data object format for XML.
    let format = |text: &str| {
        let format = between(text, "<xades:DataObjectFormat", "</xades:DataObjectFormat>");
        format[format.find('>').unwrap()..].to_string()
    };
    assert_eq!(format(&ours), format(&theirs));

    // The document is kept as it was, with the signature as the last child.
    let original = text(&fixture("doc.xml"));
    let end = original.rfind("</documento>").unwrap();
    assert!(ours.starts_with(&original[..end]));
    assert!(ours.ends_with("</ds:Signature></documento>\n"));

    // Binary data: Base64 with its MIME type.
    let ours = text(
        &sign(
            &fixture("doc.txt"),
            key,
            &params(XadesFormat::Enveloping, DigestAlgorithm::Sha512, false),
        )
        .unwrap(),
    );
    let theirs = text(&fixture("autofirma-binary-enveloping-rsa.xsig"));
    assert_eq!(format(&ours), format(&theirs));
    assert!(ours.contains(r#"MimeType="text/plain">SG9sYSBhdXRvZmlybWEtcnMK</ds:Object>"#));
}

#[test]
fn detects_tampering() {
    let key = &load("rsa.p12")[0];
    let signed = text(
        &sign(
            &fixture("doc.xml"),
            key,
            &params(XadesFormat::Enveloped, DigestAlgorithm::Sha256, false),
        )
        .unwrap(),
    );
    let status = |xml: String| {
        verify(xml.as_bytes(), None).unwrap().signatures[0]
            .signer
            .status
            .clone()
    };
    assert_eq!(status(signed.clone()), SignerStatus::Valid);
    assert_eq!(
        status(signed.replace("Documento de prueba", "Documento falso")),
        SignerStatus::DigestMismatch
    );
    assert_eq!(
        status(signed.replace("2026-10-19T18:56:23", "2026-10-19T18:56:24")),
        SignerStatus::DigestMismatch
    );
    // Another signature value.
    let value = between(&signed, "SignatureValue\">", "</ds:SignatureValue>");
    let tampered = value.replacen("SignatureValue\">", "SignatureValue\">AAAA", 1);
    let tampered = tampered.replacen(&tampered[18..22], "", 1);
    assert_eq!(
        status(signed.replace(value, &tampered)),
        SignerStatus::InvalidSignature
    );
}

#[test]
fn keeps_the_encoding_and_odd_roots() {
    let key = &load("ec.p12")[0];
    let params = params(XadesFormat::Enveloped, DigestAlgorithm::Sha256, false);

    let latin1 =
        b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<a xmlns=\"urn:x\">Espa\xf1a</a>";
    let signed = sign(latin1, key, &params).unwrap();
    assert!(signed.starts_with(&latin1[..latin1.len() - 4]));
    // City written in ISO-8859-1.
    assert!(signed.windows(5).any(|w| w == b"Alcal"));
    assert!(!signed.windows(2).any(|w| w == "á".as_bytes()));
    assert!(verify(&signed, None).unwrap().is_valid());

    let empty = sign(b"<a xmlns=\"urn:x\" Id=\"raiz\"/>", key, &params).unwrap();
    let empty_text = text(&empty);
    assert!(empty_text.starts_with("<a xmlns=\"urn:x\" Id=\"raiz\"><ds:Signature"));
    assert!(empty_text.ends_with("</ds:Signature></a>"));
    // The root has an Id: the reference points to it.
    assert!(empty_text.contains("URI=\"#raiz\""));
    assert!(verify(&empty, None).unwrap().is_valid());

    // Entities from a DOCTYPE are expanded in enveloping signatures.
    let doctype = b"<!DOCTYPE a [<!ENTITY e \"entidad\">]><a>&e;</a>";
    let params = XadesParams {
        format: XadesFormat::Enveloping,
        ..params
    };
    let signed = text(&sign(doctype, key, &params).unwrap());
    assert!(signed.contains("<a>entidad</a>"), "{signed}");
    assert!(verify(signed.as_bytes(), None).unwrap().is_valid());
}

#[test]
fn signature_timestamps() {
    let key = &load("rsa.p12")[0];
    let signed = sign(
        &fixture("doc.xml"),
        key,
        &params(XadesFormat::Enveloped, DigestAlgorithm::Sha256, false),
    )
    .unwrap();
    let imprints = timestamp_imprints(&signed, DigestAlgorithm::Sha512).unwrap();
    assert_eq!(imprints.len(), 1);
    let request = crate::tsp::request(DigestAlgorithm::Sha512, &imprints[0], None).unwrap();
    let response = tsa_response(&request, "20261019165624Z");
    let stamped = add_timestamps(
        &signed,
        DigestAlgorithm::Sha512,
        std::slice::from_ref(&response),
    )
    .unwrap();
    assert!(text(&stamped).contains("<xades:UnsignedProperties"));

    let report = verify(&stamped, None).unwrap();
    assert!(report.is_valid(), "{report:?}");
    let timestamps = &report.signatures[0].signer.timestamps;
    assert_eq!(timestamps.len(), 1);
    assert_eq!(timestamps[0].status, SignerStatus::Valid);
    assert_eq!(timestamps[0].time, Some(SIGNING_TIME + 1));
    // Already timestamped: nothing left to timestamp.
    assert!(
        timestamp_imprints(&stamped, DigestAlgorithm::Sha512)
            .unwrap()
            .is_empty()
    );
    // A response for other data is rejected.
    let other = tsa_response(
        &crate::tsp::request(DigestAlgorithm::Sha512, &[0; 64], None).unwrap(),
        "20261019165624Z",
    );
    assert!(add_timestamps(&signed, DigestAlgorithm::Sha512, &[other]).is_err());
}
