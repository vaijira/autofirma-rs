use std::time::Duration;

use thirtyfour::{prelude::*, stringmatch::StringMatch};

const APP_URL: &str = "http://localhost:8080/";
const WEBDRIVER_URL: &str = "http://localhost:4444";

/// Directory with `tests/data` as seen by the browser. Defaults to the mount point in
/// the selenium container; set `E2E_TEST_DATA` when running a local driver.
fn test_data() -> String {
    std::env::var("E2E_TEST_DATA").unwrap_or_else(|_| "/test_data".to_string())
}

/// Chrome by default (docker-compose); `E2E_BROWSER=firefox` for a local geckodriver.
async fn driver() -> WebDriverResult<WebDriver> {
    let driver = if std::env::var("E2E_BROWSER").as_deref() == Ok("firefox") {
        let mut caps = DesiredCapabilities::firefox();
        caps.set_headless()?;
        WebDriver::new(WEBDRIVER_URL, caps).await?
    } else {
        let mut caps = DesiredCapabilities::chrome();
        caps.set_headless()?;
        WebDriver::new(WEBDRIVER_URL, caps).await?
    };
    driver.goto(APP_URL).await?;
    Ok(driver)
}

/// Waits for an element; prints the page source if it never shows up.
async fn wait(driver: &WebDriver, by: By) -> WebDriverResult<WebElement> {
    match driver
        .query(by)
        .wait(Duration::from_secs(10), Duration::from_millis(200))
        .first()
        .await
    {
        Ok(element) => Ok(element),
        Err(err) => {
            eprintln!("Page source on failure:\n{}", driver.source().await?);
            Err(err)
        }
    }
}

/// Waits for an element whose text contains `text`; returns its text, or the
/// current text if it never matches (so the assertion shows it).
async fn wait_text(driver: &WebDriver, id: &str, text: &str) -> WebDriverResult<String> {
    let found = driver
        .query(By::Id(id))
        .with_text(StringMatch::new(text).partial())
        .wait(Duration::from_secs(10), Duration::from_millis(200))
        .first()
        .await;
    match found {
        Ok(element) => element.text().await,
        Err(_) => wait(driver, By::Id(id)).await?.text().await,
    }
}

/// Opens files as if chosen with "Seleccionar ficheros" (one path per file).
async fn open_files(driver: &WebDriver, files: &[&str]) -> WebDriverResult<()> {
    let paths: Vec<String> = files
        .iter()
        .map(|file| format!("{}/{file}", test_data()))
        .collect();
    wait(driver, By::Id("file_input"))
        .await?
        .send_keys(paths.join("\n"))
        .await
}

/// Opens one file and waits until it replaces the previous one.
async fn open_one(driver: &WebDriver, file: &str) -> WebDriverResult<()> {
    open_files(driver, &[file]).await?;
    let name = file.rsplit('/').next().unwrap_or(file);
    let shown = wait_text(driver, "file_name", name).await?;
    assert_eq!(shown, name);
    Ok(())
}

/// Opens one file and waits for its sign panel.
async fn open_file(driver: &WebDriver, file: &str) -> WebDriverResult<()> {
    open_one(driver, file).await?;
    wait(driver, By::Id("sign_button")).await?;
    Ok(())
}

/// Unfolds "Personalizar" in the sign panel.
async fn customize(driver: &WebDriver) -> WebDriverResult<()> {
    let details = wait(driver, By::Id("sign_customize")).await?;
    if details.attr("open").await?.is_none() {
        details.find(By::Tag("summary")).await?.click().await?;
    }
    Ok(())
}

/// Selects `value` in the `<select>` with `id`.
async fn choose(driver: &WebDriver, id: &str, value: &str) -> WebDriverResult<()> {
    wait(driver, By::Id(id))
        .await?
        .find(By::Css(format!("option[value='{value}']")))
        .await?
        .click()
        .await
}

/// Imports `certs/rsa.p12` from the header button, trying a wrong password first.
async fn import_certificate(driver: &WebDriver) -> WebDriverResult<()> {
    let button = wait(driver, By::Id("cert_button")).await?;
    assert!(button.text().await?.contains("Importar certificado"));
    button.click().await?;

    wait(driver, By::Id("import_p12"))
        .await?
        .send_keys(format!("{}/certs/rsa.p12", test_data()))
        .await?;

    // Wrong password first: the dialog stays open with an error.
    wait(driver, By::Id("p12_password"))
        .await?
        .send_keys("bad")
        .await?;
    driver.find(By::Id("p12_unlock")).await?.click().await?;
    let error = wait(driver, By::Css("#p12_form [role=alert]")).await?;
    assert!(error.text().await?.contains("contraseña"));

    let password = driver.find(By::Id("p12_password")).await?;
    password.clear().await?;
    password.send_keys("1234").await?;
    driver.find(By::Id("p12_unlock")).await?.click().await?;

    // The dialog closes and the header shows the certificate.
    let name = wait_text(driver, "cert_button", "ESPAÑOL ESPAÑOL JUAN").await?;
    assert!(name.contains("ESPAÑOL ESPAÑOL JUAN"), "{name}");
    assert!(driver.find(By::Id("cert_dialog")).await.is_err());
    Ok(())
}

/// Signs with the current options; returns the result, or the error if signing failed.
async fn sign(driver: &WebDriver) -> WebDriverResult<String> {
    driver.find(By::Id("sign_button")).await?.click().await?;
    let result = wait(
        driver,
        By::Css("#signature_result, #sign_card [role=alert]"),
    )
    .await?;
    result.text().await
}

#[tokio::test]
#[ignore]
async fn analyzes_a_pdf_in_the_worker() -> WebDriverResult<()> {
    let driver = driver().await?;
    open_file(&driver, "pades/doc.pdf").await?;

    let sha256 = driver
        .find(By::Id("file_sha256"))
        .await?
        .prop("textContent")
        .await?
        .unwrap_or_default();
    assert_eq!(sha256.len(), 64);
    // The defaults are stated before anything is changed.
    let format = wait_text(&driver, "summary_format", "PAdES").await?;
    assert_eq!(format, "PAdES, dentro del PDF");
    let digest = driver.find(By::Id("summary_digest")).await?.text().await?;
    assert_eq!(digest, "SHA-512");
    let visible = driver.find(By::Id("summary_visible")).await?.text().await?;
    assert_eq!(visible, "Firma invisible");
    // Unsigned: nothing to verify.
    assert!(driver.find(By::Id("verify_card")).await.is_err());

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn imports_certificate_and_signs_cades() -> WebDriverResult<()> {
    let driver = driver().await?;
    import_certificate(&driver).await?;

    open_file(&driver, "cades/doc.txt").await?;
    let certificate = driver
        .find(By::Id("sign_certificate"))
        .await?
        .text()
        .await?;
    assert!(certificate.contains("JUAN"), "{certificate}");
    let result = sign(&driver).await?;
    assert!(result.contains("Firma CAdES generada"), "{result}");
    assert!(result.contains("doc.txt.csig"), "{result}");
    driver.find(By::Id("download_signature")).await?;

    // The new signature opens verified, with the signed data already known.
    driver
        .find(By::Id("verify_signature"))
        .await?
        .click()
        .await?;
    let summary = wait_text(&driver, "verify_summary", "Firma CAdES explícita").await?;
    assert!(summary.contains("Firmas válidas"), "{summary}");

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn asks_for_a_certificate_when_signing_without_one() -> WebDriverResult<()> {
    let driver = driver().await?;
    open_file(&driver, "cades/doc.txt").await?;
    let button = driver.find(By::Id("sign_button")).await?;
    assert_eq!(button.text().await?, "Elegir certificado y firmar");
    button.click().await?;
    wait(&driver, By::Id("cert_dialog")).await?;
    wait(&driver, By::Id("import_p12")).await?;

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn signs_a_pdf_with_a_visible_signature() -> WebDriverResult<()> {
    let driver = driver().await?;
    import_certificate(&driver).await?;

    open_file(&driver, "pades/doc-xref.pdf").await?;
    customize(&driver).await?;
    wait(&driver, By::Id("pades_options")).await?;
    driver
        .find(By::Id("sign_reason"))
        .await?
        .send_keys("Conformidad")
        .await?;
    driver.find(By::Id("sign_visible")).await?.click().await?;

    // Page 1 of 2, and the area typed in the fields.
    choose(&driver, "sign_page", "1").await?;
    let width = driver.find(By::Id("sign_width")).await?;
    width.clear().await?;
    width.send_keys("250\t").await?;
    driver
        .find(By::Id("sign_text"))
        .await?
        .send_keys("Firmado por $$SUBJECTCN$$")
        .await?;
    let visible = wait_text(&driver, "summary_visible", "página 1").await?;
    assert_eq!(visible, "Visible en la página 1");

    let result = sign(&driver).await?;
    assert!(result.contains("PDF firmado en PAdES"), "{result}");
    assert!(result.contains("doc-xref_signed.pdf"), "{result}");

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn signs_an_encrypted_pdf() -> WebDriverResult<()> {
    let driver = driver().await?;
    import_certificate(&driver).await?;

    open_file(&driver, "pades/doc-aes256.pdf").await?;
    wait(&driver, By::Id("pdf_password"))
        .await?
        .send_keys("user")
        .await?;
    driver.find(By::Id("pdf_unlock")).await?.click().await?;
    wait(&driver, By::Id("pades_options")).await?;

    let result = sign(&driver).await?;
    assert!(result.contains("PDF firmado en PAdES"), "{result}");

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn verifies_signatures() -> WebDriverResult<()> {
    let driver = driver().await?;

    // Signed PDF made by AutoFirma: two signatures, verified on opening.
    open_one(&driver, "pades/autofirma-cosign-ec.pdf").await?;
    let summary = wait_text(&driver, "verify_summary", "2 firma").await?;
    assert!(summary.contains("Firmas válidas"), "{summary}");
    // And ready for one more.
    let title = driver.find(By::Id("sign_title")).await?.text().await?;
    assert_eq!(title, "Añadir su firma");

    // Explicit CAdES: asks for the signed file.
    open_one(&driver, "cades/autofirma-explicit-rsa.csig").await?;
    wait(&driver, By::Id("verify_data"))
        .await?
        .send_keys(format!("{}/cades/doc.txt", test_data()))
        .await?;
    let summary = wait_text(&driver, "verify_summary", "Firma CAdES explícita").await?;
    assert!(summary.contains("Firmas válidas"), "{summary}");

    // Encrypted PDF: asks for the password.
    open_one(&driver, "pades/autofirma-aes256-rsa.pdf").await?;
    wait(&driver, By::Id("pdf_password"))
        .await?
        .send_keys("user")
        .await?;
    driver.find(By::Id("pdf_unlock")).await?.click().await?;
    let summary = wait_text(&driver, "verify_summary", "Firmas válidas").await?;
    assert!(summary.contains("Firmas válidas"), "{summary}");

    driver.quit().await
}

/// Needs the test server from `tools/triphase-server/run.sh`; skipped unless
/// `TRIPHASE_URL` is set (for instance to
/// `http://127.0.0.1:8090/afirma-server-triphase-signer/SignatureService`).
#[tokio::test]
#[ignore]
async fn signs_a_pdf_through_a_triphase_server() -> WebDriverResult<()> {
    let Ok(server) = std::env::var("TRIPHASE_URL") else {
        eprintln!("TRIPHASE_URL not set, skipping");
        return Ok(());
    };
    let driver = driver().await?;
    import_certificate(&driver).await?;

    open_file(&driver, "pades/doc.pdf").await?;
    wait(&driver, By::Id("pades_options")).await?;
    customize(&driver).await?;
    driver.find(By::Id("sign_triphase")).await?.click().await?;
    wait(&driver, By::Id("sign_server"))
        .await?
        .send_keys(&server)
        .await?;
    let result = sign(&driver).await?;
    assert!(result.contains("PDF firmado en PAdES"), "{result}");

    // A co-signature of a CAdES signature, on the same server (the options stay).
    open_file(&driver, "cades/autofirma-implicit-age-rsa.csig").await?;
    wait(&driver, By::Id("summary_triphase")).await?;
    let result = sign(&driver).await?;
    assert!(result.contains("Cofirma CAdES generada"), "{result}");

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn signs_xml_in_xades_facturae_and_asic() -> WebDriverResult<()> {
    let driver = driver().await?;
    import_certificate(&driver).await?;

    // XML: XAdES preselected; enveloped.
    open_file(&driver, "xades/doc.xml").await?;
    let format = wait_text(&driver, "summary_format", "XAdES").await?;
    assert_eq!(format, "XAdES envolvente");
    customize(&driver).await?;
    choose(&driver, "sign_xades_format", "enveloped").await?;
    let format = wait_text(&driver, "summary_format", "dentro del XML").await?;
    assert_eq!(format, "XAdES dentro del XML");
    let result = sign(&driver).await?;
    assert!(result.contains("Firma XAdES generada"), "{result}");
    assert!(result.contains("doc.xml.xsig"), "{result}");

    // FacturaE invoice: detected and signed as such.
    open_file(&driver, "xades/factura.xml").await?;
    let format = wait_text(&driver, "summary_format", "FacturaE").await?;
    assert_eq!(format, "FacturaE, como emisor");
    let result = sign(&driver).await?;
    assert!(result.contains("Factura electrónica firmada"), "{result}");

    // Binary data in a CAdES ASiC-S container.
    open_file(&driver, "xades/doc.txt").await?;
    customize(&driver).await?;
    wait(&driver, By::Id("sign_asic")).await?.click().await?;
    let result = sign(&driver).await?;
    assert!(
        result.contains("Contenedor ASiC-S con firma CAdES"),
        "{result}"
    );
    assert!(result.contains("doc.txt.asics"), "{result}");

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn verifies_xml_and_asic_signatures() -> WebDriverResult<()> {
    let driver = driver().await?;
    for (file, expected) in [
        (
            "xades/autofirma-enveloped-age-rsa.xsig",
            "Documento XML con 1 firma",
        ),
        (
            "xades/autofirma-facturae-rsa.xsig",
            "Documento XML con 1 firma",
        ),
        ("asic/autofirma-xades-rsa.asics", "Contenedor ASiC-S"),
    ] {
        open_one(&driver, file).await?;
        let summary = wait_text(&driver, "verify_summary", expected).await?;
        assert!(
            summary.contains("Firmas válidas") && summary.contains(expected),
            "{file}: {summary}"
        );
    }
    driver.quit().await
}

/// Needs a TSA that allows the app's origin, such as `tools/tsa-server/tsa.py`;
/// skipped unless `TSA_URL` is set (for instance to `http://127.0.0.1:8091/`).
#[tokio::test]
#[ignore]
async fn signs_with_timestamps() -> WebDriverResult<()> {
    let Ok(tsa) = std::env::var("TSA_URL") else {
        eprintln!("TSA_URL not set, skipping");
        return Ok(());
    };
    let driver = driver().await?;
    import_certificate(&driver).await?;

    // PDF: signature and document timestamps.
    open_file(&driver, "pades/doc.pdf").await?;
    wait(&driver, By::Id("pades_options")).await?;
    customize(&driver).await?;
    driver.find(By::Id("sign_timestamp")).await?.click().await?;
    wait(&driver, By::Id("sign_tsa"))
        .await?
        .send_keys(&tsa)
        .await?;
    choose(&driver, "sign_pdf_timestamp", "both").await?;
    let result = sign(&driver).await?;
    assert!(result.contains("con sello de tiempo"), "{result}");

    // XAdES-T: the timestamp options stay set for the next file.
    open_file(&driver, "xades/doc.xml").await?;
    let stamp = driver
        .find(By::Id("summary_timestamp"))
        .await?
        .text()
        .await?;
    assert_eq!(stamp, "Con sello de tiempo");
    let result = sign(&driver).await?;
    assert!(
        result.contains("Firma XAdES generada con sello de tiempo"),
        "{result}"
    );

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn cosigns_and_countersigns_signatures() -> WebDriverResult<()> {
    let driver = driver().await?;
    import_certificate(&driver).await?;

    // A CAdES signature: co-signed by default.
    open_file(&driver, "cades/autofirma-implicit-age-rsa.csig").await?;
    let note = wait(&driver, By::Id("sign_note")).await?.text().await?;
    assert!(note.contains("cofirma"), "{note}");
    let format = driver.find(By::Id("summary_format")).await?.text().await?;
    assert_eq!(format, "Cofirma CAdES");
    assert!(driver.find(By::Id("sign_format")).await.is_err());
    let result = sign(&driver).await?;
    assert!(result.contains("Cofirma CAdES generada"), "{result}");
    assert!(
        result.contains("autofirma-implicit-age-rsa_cosigned.csig"),
        "{result}"
    );

    // Counter-sign every signature of a XAdES signature.
    open_file(&driver, "xades/autofirma-enveloped-rsa.xsig").await?;
    customize(&driver).await?;
    choose(&driver, "sign_operation", "tree").await?;
    let result = sign(&driver).await?;
    assert!(result.contains("Contrafirma XAdES generada"), "{result}");
    assert!(result.contains("_countersigned.xsig"), "{result}");

    // Or sign the signature as plain data.
    open_file(&driver, "cades/autofirma-explicit-rsa.csig").await?;
    customize(&driver).await?;
    choose(&driver, "sign_operation", "sign").await?;
    wait(&driver, By::Id("sign_format")).await?;
    let result = sign(&driver).await?;
    assert!(result.contains("Firma CAdES generada"), "{result}");

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn signs_office_documents() -> WebDriverResult<()> {
    let driver = driver().await?;
    import_certificate(&driver).await?;

    for (file, format, signed) in [
        ("odf/doc.odt", "ODF", "doc_signed.odt"),
        ("ooxml/doc.docx", "OOXML", "doc_signed.docx"),
        // Signed by AutoFirma: one more signature.
        ("odf/autofirma-rsa.odt", "ODF", "autofirma-rsa_signed.odt"),
    ] {
        open_file(&driver, file).await?;
        let shown = wait_text(&driver, "summary_format", format).await?;
        assert_eq!(shown, format!("{format}, dentro del documento"));
        let result = sign(&driver).await?;
        assert!(
            result.contains(&format!("Documento firmado en {format}")),
            "{file}: {result}"
        );
        assert!(result.contains(signed), "{file}: {result}");
    }

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn signs_many_files_into_a_zip() -> WebDriverResult<()> {
    let driver = driver().await?;
    import_certificate(&driver).await?;

    open_files(
        &driver,
        &[
            "pades/doc.pdf",
            "xades/doc.xml",
            "cades/doc.txt",
            "odf/doc.odt",
        ],
    )
    .await?;
    let button = driver
        .query(By::Id("batch_sign_button"))
        .with_text("Firmar 4 ficheros")
        .wait(Duration::from_secs(10), Duration::from_millis(200))
        .first()
        .await?;
    button.click().await?;
    let summary = wait(&driver, By::Id("batch_summary")).await?.text().await?;
    assert_eq!(summary, "4 de 4 fichero(s) firmados.");
    let result = driver.find(By::Id("batch_result")).await?.text().await?;
    for name in [
        "doc_signed.pdf",
        "doc.xml.xsig",
        "doc.txt.csig",
        "doc_signed.odt",
    ] {
        assert!(result.contains(name), "{name}: {result}");
    }
    driver.find(By::Id("batch_download")).await?;

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn verifies_office_documents_and_countersignatures() -> WebDriverResult<()> {
    let driver = driver().await?;
    for (file, expected) in [
        (
            "cades/autofirma-countersign-ec.csig",
            "con 2 firmante(s) y 2 contrafirma(s)",
        ),
        (
            "xades/autofirma-countersign-ec.xsig",
            "Documento XML con 1 firma(s) y 1 contrafirma(s)",
        ),
        (
            "odf/autofirma-rsa.odt",
            "Documento OpenDocument con 1 firma",
        ),
        (
            "ooxml/autofirma-rsa.docx",
            "Documento Office (OOXML) con 1 firma",
        ),
    ] {
        open_one(&driver, file).await?;
        let summary = wait_text(&driver, "verify_summary", expected).await?;
        assert!(
            summary.contains("Firmas válidas") && summary.contains(expected),
            "{file}: {summary}"
        );
    }
    // Counter-signatures are shown under their signature.
    let depths = driver
        .find_all(By::Css("#verify_result article[data-depth='1']"))
        .await?;
    assert!(
        depths.is_empty(),
        "the last document has no counter-signatures"
    );

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn remembers_changed_options() -> WebDriverResult<()> {
    let driver = driver().await?;

    open_file(&driver, "cades/doc.txt").await?;
    customize(&driver).await?;
    choose(&driver, "sign_digest", "sha256").await?;
    let digest = wait(&driver, By::Id("summary_digest")).await?;
    assert_eq!(digest.text().await?, "SHA-256");
    assert_eq!(digest.attr("title").await?.as_deref(), Some("Cambiado"));

    // Still there after a reload.
    driver.refresh().await?;
    open_file(&driver, "cades/doc.txt").await?;
    let digest = wait_text(&driver, "summary_digest", "SHA-256").await?;
    assert_eq!(digest, "SHA-256");

    // Until reset.
    customize(&driver).await?;
    driver.find(By::Id("sign_reset")).await?.click().await?;
    let digest = wait_text(&driver, "summary_digest", "SHA-512").await?;
    assert_eq!(digest, "SHA-512");

    driver.quit().await
}
