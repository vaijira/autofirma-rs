use std::cell::RefCell;

use anyhow::{Result, anyhow};
use js_sys::{Array, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{Blob, BlobPropertyBag, HtmlAnchorElement, Url};

thread_local! {
    /// Object URL of the last download, revoked when the next one is created.
    static LAST_DOWNLOAD_URL: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Offers `data` to the user as a file download named `file_name`.
pub fn download(data: &[u8], file_name: &str, mime_type: &str) -> Result<()> {
    let properties = BlobPropertyBag::new();
    properties.set_type(mime_type);
    let parts = Array::of1(&Uint8Array::from(data));
    let blob = Blob::new_with_u8_array_sequence_and_options(&JsValue::from(parts), &properties)
        .map_err(|e| anyhow!("No se pudo crear el fichero: {e:?}"))?;
    let url = Url::create_object_url_with_blob(&blob)
        .map_err(|e| anyhow!("No se pudo crear la URL: {e:?}"))?;

    let link: HtmlAnchorElement = gloo_utils::document()
        .create_element("a")
        .map_err(|e| anyhow!("{e:?}"))?
        .unchecked_into();
    link.set_href(&url);
    link.set_download(file_name);
    link.click();

    if let Some(previous) = LAST_DOWNLOAD_URL.with(|last| last.replace(Some(url))) {
        let _ = Url::revoke_object_url(&previous);
    }
    Ok(())
}
