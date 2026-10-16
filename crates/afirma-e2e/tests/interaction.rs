use std::time::Duration;

use thirtyfour::prelude::*;

const APP_URL: &str = "http://localhost:8080/";
const WEBDRIVER_URL: &str = "http://localhost:4444";

/// Directory with `tests/data` as seen by the browser. Defaults to the mount point in
/// the selenium container; set `E2E_TEST_DATA` when running a local driver.
fn test_data() -> String {
    std::env::var("E2E_TEST_DATA").unwrap_or_else(|_| "/test_data".to_string())
}

/// Chrome by default (docker-compose); `E2E_BROWSER=firefox` for a local geckodriver.
async fn driver() -> WebDriverResult<WebDriver> {
    if std::env::var("E2E_BROWSER").as_deref() == Ok("firefox") {
        let mut caps = DesiredCapabilities::firefox();
        caps.set_headless()?;
        WebDriver::new(WEBDRIVER_URL, caps).await
    } else {
        let mut caps = DesiredCapabilities::chrome();
        caps.set_headless()?;
        WebDriver::new(WEBDRIVER_URL, caps).await
    }
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

#[tokio::test]
#[ignore]
async fn analyzes_a_pdf_in_the_worker() -> WebDriverResult<()> {
    let driver = driver().await?;
    driver.goto(APP_URL).await?;

    wait(&driver, By::Id("sign_file"))
        .await?
        .send_keys(format!("{}/pades/doc.pdf", test_data()))
        .await?;

    let sha256 = wait(&driver, By::Css("#file_sha256 td")).await?;
    assert_eq!(sha256.text().await?.len(), 64);
    let format = driver
        .find(By::Css("#file_format td"))
        .await?
        .text()
        .await?;
    assert_eq!(format, "PAdES");

    driver.quit().await
}

/// Imports `certs/rsa.p12` in the "Certificados" view, trying a wrong password first.
async fn import_certificate(driver: &WebDriver) -> WebDriverResult<()> {
    driver.goto(format!("{APP_URL}#/certs")).await?;

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
    let error = wait(driver, By::Css("form[role=dialog] [role=alert]")).await?;
    assert!(error.text().await?.contains("contraseña"));

    let password = driver.find(By::Id("p12_password")).await?;
    password.clear().await?;
    password.send_keys("1234").await?;
    driver.find(By::Id("p12_unlock")).await?.click().await?;

    let card = wait(driver, By::Css("#cert_list article")).await?;
    assert!(card.text().await?.contains("ESPAÑOL ESPAÑOL JUAN"));
    Ok(())
}

/// Text of the signature result, or of the error if signing failed.
async fn signature_result(driver: &WebDriver) -> WebDriverResult<String> {
    let result = wait(driver, By::Css("#signature_result, [role=alert]")).await?;
    result.text().await
}

#[tokio::test]
#[ignore]
async fn imports_certificate_and_signs_cades() -> WebDriverResult<()> {
    let driver = driver().await?;
    import_certificate(&driver).await?;

    driver.find(By::LinkText("Firmar")).await?.click().await?;
    wait(&driver, By::Id("sign_file"))
        .await?
        .send_keys(format!("{}/cades/doc.txt", test_data()))
        .await?;
    wait(&driver, By::Id("sign_button")).await?;
    let certificate = driver
        .find(By::Id("sign_certificate"))
        .await?
        .text()
        .await?;
    assert!(certificate.contains("JUAN"), "{certificate}");
    driver.find(By::Id("sign_button")).await?.click().await?;

    let result = signature_result(&driver).await?;
    assert!(result.contains("Firma CAdES generada"), "{result}");
    let download = driver
        .find(By::Id("download_signature"))
        .await?
        .text()
        .await?;
    assert!(download.contains("doc.txt.csig"), "{download}");

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn signs_a_pdf_with_a_visible_signature() -> WebDriverResult<()> {
    let driver = driver().await?;
    import_certificate(&driver).await?;

    driver.find(By::LinkText("Firmar")).await?.click().await?;
    wait(&driver, By::Id("sign_file"))
        .await?
        .send_keys(format!("{}/pades/doc-xref.pdf", test_data()))
        .await?;
    // PAdES is preselected for PDFs.
    wait(&driver, By::Id("pades_options")).await?;
    driver
        .find(By::Id("sign_reason"))
        .await?
        .send_keys("Conformidad")
        .await?;
    driver.find(By::Id("sign_visible")).await?.click().await?;

    // Page 1 of 2, and the area typed in the fields.
    wait(&driver, By::Id("sign_page"))
        .await?
        .find(By::Css("option[value='1']"))
        .await?
        .click()
        .await?;
    let width = driver.find(By::Id("sign_width")).await?;
    width.clear().await?;
    width.send_keys("250\t").await?;
    driver
        .find(By::Id("sign_text"))
        .await?
        .send_keys("Firmado por $$SUBJECTCN$$")
        .await?;

    driver.find(By::Id("sign_button")).await?.click().await?;
    let result = signature_result(&driver).await?;
    assert!(result.contains("PDF firmado en PAdES"), "{result}");
    let download = driver
        .find(By::Id("download_signature"))
        .await?
        .text()
        .await?;
    assert!(download.contains("doc-xref_signed.pdf"), "{download}");

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn signs_an_encrypted_pdf() -> WebDriverResult<()> {
    let driver = driver().await?;
    import_certificate(&driver).await?;

    driver.find(By::LinkText("Firmar")).await?.click().await?;
    wait(&driver, By::Id("sign_file"))
        .await?
        .send_keys(format!("{}/pades/doc-aes256.pdf", test_data()))
        .await?;
    wait(&driver, By::Id("pdf_password"))
        .await?
        .send_keys("user")
        .await?;
    driver.find(By::Id("pdf_unlock")).await?.click().await?;
    wait(&driver, By::Id("pades_options")).await?;

    driver.find(By::Id("sign_button")).await?.click().await?;
    let result = signature_result(&driver).await?;
    assert!(result.contains("PDF firmado en PAdES"), "{result}");

    driver.quit().await
}

#[tokio::test]
#[ignore]
async fn verifies_signatures() -> WebDriverResult<()> {
    let driver = driver().await?;
    driver.goto(format!("{APP_URL}#/verify")).await?;

    // Signed PDF made by AutoFirma: two signatures.
    wait(&driver, By::Id("verify_file"))
        .await?
        .send_keys(format!("{}/pades/autofirma-cosign-ec.pdf", test_data()))
        .await?;
    let summary = wait(&driver, By::Id("verify_summary"))
        .await?
        .text()
        .await?;
    assert!(
        summary.contains("Firmas válidas") && summary.contains("2 firma"),
        "{summary}"
    );

    // Explicit CAdES: asks for the signed file.
    driver
        .find(By::Id("verify_file"))
        .await?
        .send_keys(format!("{}/cades/autofirma-explicit-rsa.csig", test_data()))
        .await?;
    wait(&driver, By::Id("verify_data"))
        .await?
        .send_keys(format!("{}/cades/doc.txt", test_data()))
        .await?;
    let summary = wait(&driver, By::Id("verify_summary"))
        .await?
        .text()
        .await?;
    assert!(summary.contains("Firma CAdES explícita"), "{summary}");

    // Encrypted PDF: asks for the password.
    driver
        .find(By::Id("verify_file"))
        .await?
        .send_keys(format!("{}/pades/autofirma-aes256-rsa.pdf", test_data()))
        .await?;
    wait(&driver, By::Id("verify_password"))
        .await?
        .send_keys("user")
        .await?;
    driver.find(By::Id("verify_unlock")).await?.click().await?;
    let summary = wait(&driver, By::Id("verify_summary"))
        .await?
        .text()
        .await?;
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

    driver.find(By::LinkText("Firmar")).await?.click().await?;
    wait(&driver, By::Id("sign_file"))
        .await?
        .send_keys(format!("{}/pades/doc.pdf", test_data()))
        .await?;
    wait(&driver, By::Id("pades_options")).await?;
    driver
        .find(By::Css("details summary"))
        .await?
        .click()
        .await?;
    driver.find(By::Id("sign_triphase")).await?.click().await?;
    driver
        .find(By::Id("sign_server"))
        .await?
        .send_keys(&server)
        .await?;

    driver.find(By::Id("sign_button")).await?.click().await?;
    let result = signature_result(&driver).await?;
    assert!(result.contains("PDF firmado en PAdES"), "{result}");

    driver.quit().await
}
