//! Web Worker entry point.
//!
//! Announces [`WorkerEvent::Ready`] once its handler is installed, then receives
//! [`afirma_core::job::Request`]s through `postMessage`, runs them and posts back
//! a [`WorkerEvent::Response`] with the same id.

#![warn(
    rust_2018_idioms,
    missing_docs,
    missing_debug_implementations,
    unused_extern_crates
)]

use std::cell::RefCell;

use afirma_core::job::{Engine, Request, WorkerEvent};
use wasm_bindgen::{JsCast, prelude::*};
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};

/// Installs the `onmessage` handler when the worker module is loaded.
#[wasm_bindgen(start)]
pub fn main_worker() -> Result<(), JsValue> {
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();
    wasm_logger::init(
        wasm_logger::Config::new(log::Level::Debug).module_prefix(env!("CARGO_PKG_NAME")),
    );

    let scope: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    // Loaded private keys live here, inside the worker, and never reach the UI thread.
    let engine = RefCell::new(Engine::new());
    let onmessage = Closure::<dyn Fn(MessageEvent)>::new({
        let scope = scope.clone();
        move |event: MessageEvent| {
            let response = match serde_wasm_bindgen::from_value::<Request>(event.data()) {
                Ok(request) => WorkerEvent::Response(engine.borrow_mut().handle(request)),
                Err(err) => {
                    log::error!("Invalid worker request: {err}");
                    return;
                }
            };
            if let Err(err) = post(&scope, &response) {
                log::error!("Unable to post worker response: {err:?}");
            }
        }
    });
    scope.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    // The handler lives as long as the worker.
    onmessage.forget();

    post(&scope, &WorkerEvent::Ready)?;
    log::debug!("Worker ready");
    Ok(())
}

fn post(scope: &DedicatedWorkerGlobalScope, event: &WorkerEvent) -> Result<(), JsValue> {
    let value = serde_wasm_bindgen::to_value(event)?;
    scope.post_message(&value)
}
