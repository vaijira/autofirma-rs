use super::*;
use crate::{
    cades::SignerStatus, format::SignatureFormat, keystore::tests::load as load_keys,
    policy::PolicyPreset,
};

// 2026-10-16T14:07:54Z
const SIGNING_TIME: i64 = 1_792_159_674;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/data/pades/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn params() -> PadesParams {
    PadesParams {
        utc_offset_minutes: 120,
        ..PadesParams::new(SIGNING_TIME)
    }
}

fn visible(pages: SignaturePages) -> VisibleSignature {
    VisibleSignature {
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
    }
}

fn assert_valid(signed: &[u8], password: Option<&str>, count: usize) -> PdfVerifyReport {
    let report = verify(signed, password).unwrap();
    assert_eq!(report.signatures.len(), count, "{report:?}");
    assert!(report.is_valid(), "{report:?}");
    assert!(report.signatures.last().unwrap().covers_whole_document);
    report
}

#[test]
fn signs_every_fixture() {
    for keystore in ["rsa.p12", "ec.p12"] {
        let key = &load_keys(keystore)[0];
        for (name, password) in [
            ("doc.pdf", None),
            ("doc-xref.pdf", None),
            ("doc-aes256.pdf", Some("user")),
            ("doc-aes256.pdf", Some("owner")),
            ("doc-rc4.pdf", None),
        ] {
            let original = fixture(name);
            let params = PadesParams {
                password: password.map(str::to_string),
                ..params()
            };
            let signed = sign(&original, key, &params).unwrap();
            // Incremental update: the original bytes are untouched.
            assert_eq!(&signed[..original.len()], original, "{keystore} {name}");
            let report = assert_valid(&signed, password, 1);
            let signature = &report.signatures[0];
            assert_eq!(signature.field, "Signature1");
            assert_eq!(signature.sub_filter, "ETSI.CAdES.detached");
            assert_eq!(
                signature.claimed_time,
                Some(SIGNING_TIME),
                "{keystore} {name}"
            );
            assert_eq!(signature.signer.digest, Some(DigestAlgorithm::Sha512));
            // PAdES: the signing time is in /M, not in the CMS.
            assert_eq!(signature.signer.signing_time, None);
        }
    }
}

#[test]
fn second_signature_keeps_the_first_one_valid() {
    let rsa = &load_keys("rsa.p12")[0];
    let ec = &load_keys("ec.p12")[0];
    let once = sign(&fixture("doc-xref.pdf"), rsa, &params()).unwrap();
    let twice = sign(
        &once,
        ec,
        &PadesParams {
            visible: Some(visible(SignaturePages::Last)),
            ..params()
        },
    )
    .unwrap();
    let report = assert_valid(&twice, None, 2);
    assert!(!report.signatures[0].covers_whole_document);
    assert_eq!(report.signatures[0].revision_length, once.len());
    assert_eq!(report.signatures[1].field, "Signature2");
    assert_eq!(info(&twice, None).unwrap().signatures, 2);
}

#[test]
fn policy_reason_and_location() {
    let key = &load_keys("rsa.p12")[0];
    let signed = sign(
        &fixture("doc.pdf"),
        key,
        &PadesParams {
            policy: Some(PolicyPreset::Age19.policy(SignatureFormat::Pades)),
            reason: Some("Conformidad".to_string()),
            location: Some("Logroño".to_string()),
            ..params()
        },
    )
    .unwrap();
    let report = assert_valid(&signed, None, 1);
    let signature = &report.signatures[0];
    assert_eq!(
        signature.signer.policy.as_deref(),
        Some("2.16.724.1.3.1.1.2.1.9")
    );
    assert_eq!(signature.reason.as_deref(), Some("Conformidad"));
    assert_eq!(signature.location.as_deref(), Some("Logroño"));
}

#[test]
fn visible_signatures() {
    let key = &load_keys("rsa.p12")[0];
    let jpeg_rubric = [
        0xff, 0xd8, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 1, 0x11, 0, 0xff,
        0xd9,
    ];
    for (pages, rubric) in [
        (SignaturePages::Last, false),
        (SignaturePages::Pages(vec![1, -1]), true),
        (SignaturePages::All, false),
        (SignaturePages::Append, false),
    ] {
        let original = fixture("doc-xref.pdf");
        let mut visible = visible(pages.clone());
        visible.text = Some("Firmado por $$SUBJECTCN$$ el $$SIGNDATE=dd/MM/yyyy$$".to_string());
        visible.image = rubric.then(|| jpeg_rubric.to_vec());
        let signed = sign(
            &original,
            key,
            &PadesParams {
                visible: Some(visible),
                ..params()
            },
        )
        .unwrap();
        assert_valid(&signed, None, 1);

        let doc = Document::load_mem(&signed).unwrap();
        let widgets: usize = doc
            .get_pages()
            .values()
            .map(|&id| {
                doc.get_dictionary(id)
                    .unwrap()
                    .get(b"Annots")
                    .and_then(Object::as_array)
                    .map_or(0, Vec::len)
            })
            .sum();
        let (expected_widgets, expected_pages) = match pages {
            SignaturePages::Last => (1, 2),
            SignaturePages::Append => (1, 3),
            _ => (2, 2),
        };
        assert_eq!(widgets, expected_widgets, "{pages:?}");
        assert_eq!(doc.get_pages().len(), expected_pages, "{pages:?}");
        let text = String::from_utf8_lossy(&signed);
        assert!(text.contains("(Firmado por ESPA"), "{pages:?}");
        assert!(text.contains("(JUAN - ***9999** el) Tj"), "{pages:?}");
        assert!(text.contains("(16/10/2026) Tj"), "{pages:?}");
    }
}

#[test]
fn visible_signature_on_rotated_page() {
    // Page 2 of doc-xref.pdf is landscape without /Rotate; rotate page 1 instead.
    let original = fixture("doc.pdf");
    let mut doc = Document::load_mem(&original).unwrap();
    let page = *doc.get_pages().get(&1).unwrap();
    doc.get_dictionary_mut(page).unwrap().set("Rotate", 90);
    let mut rotated = Vec::new();
    doc.save_to(&mut rotated).unwrap();

    let key = &load_keys("rsa.p12")[0];
    assert_eq!(info(&rotated, None).unwrap().pages, [(842.0, 595.0)]);
    let signed = sign(
        &rotated,
        key,
        &PadesParams {
            visible: Some(visible(SignaturePages::Last)),
            ..params()
        },
    )
    .unwrap();
    assert_valid(&signed, None, 1);
    let doc = Document::load_mem(&signed).unwrap();
    let widget = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .find(|d| d.has(b"FT"))
        .unwrap();
    // Displayed (72, 72)-(272, 142) on a page rotated 90 degrees clockwise.
    let rect: Vec<f32> = widget
        .get(b"Rect")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_float().unwrap())
        .collect();
    assert_eq!(rect, [453.0, 72.0, 523.0, 272.0]);
}

#[test]
fn rejects_invalid_positions() {
    let key = &load_keys("rsa.p12")[0];
    let mut visible = visible(SignaturePages::Last);
    visible.rect.llx = 1000.0;
    visible.rect.urx = 1100.0;
    let err = sign(
        &fixture("doc.pdf"),
        key,
        &PadesParams {
            visible: Some(visible),
            ..params()
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::InvalidSignaturePosition(_)), "{err:?}");
}

#[test]
fn certification() {
    let key = &load_keys("rsa.p12")[0];
    let certified = sign(
        &fixture("doc.pdf"),
        key,
        &PadesParams {
            certification: CertificationLevel::NoChanges,
            ..params()
        },
    )
    .unwrap();
    let report = assert_valid(&certified, None, 1);
    assert_eq!(
        report.signatures[0].certification,
        Some(CertificationLevel::NoChanges)
    );
    assert_eq!(
        info(&certified, None).unwrap().certification,
        CertificationLevel::NoChanges
    );

    // No more signatures unless explicitly allowed.
    assert!(matches!(
        sign(&certified, key, &params()),
        Err(Error::PdfCertified)
    ));
    let forced = sign(
        &certified,
        key,
        &PadesParams {
            allow_signing_certified: true,
            ..params()
        },
    )
    .unwrap();
    assert_valid(&forced, None, 2);

    // Form filling allows signatures.
    let form_filling = sign(
        &fixture("doc.pdf"),
        key,
        &PadesParams {
            certification: CertificationLevel::FormFilling,
            ..params()
        },
    )
    .unwrap();
    assert_valid(&sign(&form_filling, key, &params()).unwrap(), None, 2);
}

#[test]
fn passwords() {
    let key = &load_keys("rsa.p12")[0];
    let encrypted = fixture("doc-aes256.pdf");
    assert!(matches!(
        sign(&encrypted, key, &params()),
        Err(Error::PdfPasswordRequired)
    ));
    assert!(matches!(
        sign(
            &encrypted,
            key,
            &PadesParams {
                password: Some("bad".to_string()),
                ..params()
            }
        ),
        Err(Error::WrongPdfPassword)
    ));
    let info = info(&encrypted, Some("user")).unwrap();
    assert!(info.encrypted);
    assert_eq!(info.pages, [(595.0, 842.0)]);
}

#[test]
fn detects_tampering() {
    let key = &load_keys("rsa.p12")[0];
    let mut signed = sign(&fixture("doc.pdf"), key, &params()).unwrap();
    // Change the page text in the original revision.
    let pos = signed.windows(8).position(|w| w == b"Pagina 1").unwrap();
    signed[pos + 7] = b'2';
    let report = verify(&signed, None).unwrap();
    assert_eq!(
        report.signatures[0].signer.status,
        SignerStatus::DigestMismatch
    );
    assert!(!report.is_valid());
}

#[test]
fn unsigned_pdf() {
    let report = verify(&fixture("doc.pdf"), None).unwrap();
    assert!(report.signatures.is_empty());
    assert!(!report.is_valid());
}

#[test]
fn verifies_autofirma_signatures() {
    for (name, count) in [
        ("autofirma-bes-rsa.pdf", 1),
        ("autofirma-age-rsa.pdf", 1),
        ("autofirma-visible-rsa.pdf", 1),
        ("autofirma-cosign-ec.pdf", 2),
    ] {
        let report = assert_valid(&fixture(name), None, count);
        assert_eq!(report.signatures[0].field, "Signature1", "{name}");
    }
    let report = assert_valid(&fixture("autofirma-aes256-rsa.pdf"), Some("user"), 1);
    assert!(report.signatures[0].signer.certificate.is_some());
    let report = verify(&fixture("autofirma-visible-rsa.pdf"), None).unwrap();
    assert_eq!(
        report.signatures[0].certification,
        Some(CertificationLevel::NoChanges)
    );
}

#[test]
fn reserved_size_is_enough_and_small() {
    let key = &load_keys("rsa.p12")[0];
    let original = fixture("doc.pdf");
    let signed = sign(&original, key, &params()).unwrap();
    // Far below AutoFirma's fixed 27000 bytes (54000 hex digits).
    assert!(signed.len() - original.len() < 16_000, "{}", signed.len());
    let err = sign(
        &original,
        key,
        &PadesParams {
            reserved_size: Some(10),
            ..params()
        },
    );
    // The estimate wins over a too small explicit size.
    assert!(err.is_ok());
}
