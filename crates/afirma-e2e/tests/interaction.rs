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

#[tokio::test]
#[ignore]
async fn analyzes_a_pdf_in_the_worker() -> WebDriverResult<()> {
    let driver = driver().await?;
    driver.goto(APP_URL).await?;

    let input = driver.find(By::Id("sign_file")).await?;
    input
        .send_keys(format!("{}/sample.pdf", test_data()))
        .await?;

    let sha256 = match driver
        .query(By::Css("#file_sha256 td"))
        .wait(Duration::from_secs(10), Duration::from_millis(200))
        .first()
        .await
    {
        Ok(element) => element,
        Err(err) => {
            eprintln!("Page source on failure:\n{}", driver.source().await?);
            driver.quit().await?;
            return Err(err);
        }
    };
    assert_eq!(sha256.text().await?.len(), 64);
    let info = driver.find(By::Id("file_info")).await?.text().await?;
    assert!(info.contains("PAdES"), "unexpected file info: {info}");

    driver.quit().await
}
