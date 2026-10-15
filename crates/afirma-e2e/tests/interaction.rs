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
        .send_keys(format!("{}/sample.pdf", test_data()))
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

#[tokio::test]
#[ignore]
async fn imports_certificate_and_signs_cades() -> WebDriverResult<()> {
    let driver = driver().await?;
    driver.goto(format!("{APP_URL}#/certs")).await?;

    wait(&driver, By::Id("import_p12"))
        .await?
        .send_keys(format!("{}/certs/rsa.p12", test_data()))
        .await?;

    // Wrong password first: the dialog stays open with an error.
    wait(&driver, By::Id("p12_password"))
        .await?
        .send_keys("bad")
        .await?;
    driver.find(By::Id("p12_unlock")).await?.click().await?;
    let error = wait(&driver, By::Css("form[role=dialog] [role=alert]")).await?;
    assert!(error.text().await?.contains("contraseña"));

    let password = driver.find(By::Id("p12_password")).await?;
    password.clear().await?;
    password.send_keys("1234").await?;
    driver.find(By::Id("p12_unlock")).await?.click().await?;

    let card = wait(&driver, By::Css("#cert_list article")).await?;
    assert!(card.text().await?.contains("ESPAÑOL ESPAÑOL JUAN"));

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

    let result = wait(&driver, By::Id("signature_result")).await?;
    assert!(result.text().await?.contains("Firma CAdES generada"));
    let download = driver
        .find(By::Id("download_signature"))
        .await?
        .text()
        .await?;
    assert!(download.contains("doc.txt.csig"), "{download}");

    driver.quit().await
}
