use anyhow::{Result, anyhow};
use js_sys::Uint8Array;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, RequestInit, Response};

/// POSTs a form (`application/x-www-form-urlencoded`) and returns the response body.
pub async fn post_form(url: &str, body: &str) -> Result<Vec<u8>> {
    let headers = Headers::new().map_err(|e| anyhow!("{e:?}"))?;
    headers
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(|e| anyhow!("{e:?}"))?;
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_headers(&headers);
    init.set_body(&body.into());

    let failed = |e| anyhow!("No se pudo conectar con el servidor de firma ({url}): {e:?}");
    let response: Response =
        JsFuture::from(gloo_utils::window().fetch_with_str_and_init(url, &init))
            .await
            .map_err(failed)?
            .unchecked_into();
    if !response.ok() {
        return Err(anyhow!(
            "El servidor de firma respondió con el error HTTP {}",
            response.status()
        ));
    }
    let buffer = JsFuture::from(response.array_buffer().map_err(failed)?)
        .await
        .map_err(failed)?;
    Ok(Uint8Array::new(&buffer).to_vec())
}
