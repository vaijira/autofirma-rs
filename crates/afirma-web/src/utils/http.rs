use anyhow::{Result, anyhow};
use js_sys::Uint8Array;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, RequestInit, Response};

/// POSTs a form (`application/x-www-form-urlencoded`) to a signature server and
/// returns the response body.
pub async fn post_form(url: &str, body: &str) -> Result<Vec<u8>> {
    post(
        url,
        "application/x-www-form-urlencoded",
        &body.into(),
        "servidor de firma",
    )
    .await
}

/// POSTs an RFC 3161 timestamp request to a TSA and returns its response.
pub async fn post_timestamp_query(url: &str, request: &[u8]) -> Result<Vec<u8>> {
    post(
        url,
        "application/timestamp-query",
        &Uint8Array::from(request).into(),
        "servidor de sellado de tiempo",
    )
    .await
}

async fn post(url: &str, content_type: &str, body: &JsValue, server: &str) -> Result<Vec<u8>> {
    let headers = Headers::new().map_err(|e| anyhow!("{e:?}"))?;
    headers
        .set("Content-Type", content_type)
        .map_err(|e| anyhow!("{e:?}"))?;
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_headers(&headers);
    init.set_body(body);

    // Usually a network error or a server that does not allow this origin (CORS).
    let failed = |e| anyhow!("No se pudo conectar con el {server} ({url}): {e:?}");
    let response: Response =
        JsFuture::from(gloo_utils::window().fetch_with_str_and_init(url, &init))
            .await
            .map_err(failed)?
            .unchecked_into();
    if !response.ok() {
        return Err(anyhow!(
            "El {server} respondió con el error HTTP {}",
            response.status()
        ));
    }
    let buffer = JsFuture::from(response.array_buffer().map_err(failed)?)
        .await
        .map_err(failed)?;
    Ok(Uint8Array::new(&buffer).to_vec())
}
