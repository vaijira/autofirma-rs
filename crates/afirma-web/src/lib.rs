//! autofirma-rs: electronic signatures in the browser.

#![warn(
    rust_2018_idioms,
    missing_docs,
    missing_debug_implementations,
    unused_extern_crates
)]

use wasm_bindgen::prelude::*;

use crate::app::App;

mod app;
mod components;
mod css;
mod prefs;
mod state;
mod utils;
mod views;
mod worker;

const APP_ID: &str = "autofirmaApp";

/// Entry point: replaces the loading placeholder in `index.html` with the app.
#[wasm_bindgen(start)]
pub async fn main_js() -> Result<(), JsValue> {
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();
    wasm_logger::init(
        wasm_logger::Config::new(log::Level::Debug).module_prefix(env!("CARGO_PKG_NAME")),
    );

    let app = App::new()?;
    let root = dominator::get_id(APP_ID);
    let placeholder = root.last_child().ok_or("missing loading placeholder")?;
    dominator::replace_dom(&root, &placeholder, App::render(app));

    Ok(())
}
