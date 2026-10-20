//! Signature options that outlive the page: saved in `localStorage` when they
//! differ from their default, so a TSA or a server is typed only once.

use std::ops::Deref;

use afirma_core::{
    cades::SignatureMode, digest::DigestAlgorithm, pades::FontFamily, policy::PolicyPreset,
    xades::XadesFormat,
};
use futures_signals::signal::{Mutable, Signal, SignalExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use wasm_bindgen_futures::spawn_local;
use web_sys::Storage;

/// Prefix of the `localStorage` keys.
const PREFIX: &str = "autofirma-rs.";

/// Timestamps of a PDF (AutoFirma's `tsType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdfTimestamp {
    /// On the signature (`1`).
    Signature,
    /// On the whole document, as a new revision (`2`).
    Document,
    /// Both (`3`).
    Both,
}

/// An option with a default value. Reads and writes go through the inner
/// [`Mutable`]; every change is saved.
#[derive(Debug)]
pub struct Pref<T> {
    default: T,
    value: Mutable<T>,
}

impl<T> Pref<T>
where
    T: Clone + PartialEq + Serialize + DeserializeOwned + 'static,
{
    fn new(key: &'static str, default: T) -> Self {
        let value = Mutable::new(load(key).unwrap_or_else(|| default.clone()));
        spawn_local(value.signal_cloned().for_each({
            let default = default.clone();
            move |value| {
                save(key, (value != default).then_some(&value));
                async {}
            }
        }));
        Self { default, value }
    }

    /// Whether the value differs from the default, updated when it changes.
    pub fn modified_signal(&self) -> impl Signal<Item = bool> + use<T> {
        let default = self.default.clone();
        self.value.signal_ref(move |value| *value != default)
    }

    pub fn reset(&self) {
        self.value.set_neq(self.default.clone());
    }
}

impl<T> Deref for Pref<T> {
    type Target = Mutable<T>;

    fn deref(&self) -> &Mutable<T> {
        &self.value
    }
}

/// The options shared by every signature, with AutoFirma's defaults.
#[derive(Debug)]
pub struct Preferences {
    pub digest: Pref<DigestAlgorithm>,
    pub policy: Pref<Option<PolicyPreset>>,
    /// CAdES explicit (detached) or implicit.
    pub cades_mode: Pref<SignatureMode>,
    /// XAdES enveloping, enveloped (XML only) or detached.
    pub xades_format: Pref<XadesFormat>,
    /// Where the signatures are made.
    pub location: Pref<String>,
    /// Visible PDF signature.
    pub visible: Pref<bool>,
    /// Visible text with AutoFirma's placeholders; empty for the default text.
    pub visible_text: Pref<String>,
    pub font_family: Pref<FontFamily>,
    pub font_size: Pref<f32>,
    pub timestamp: Pref<bool>,
    pub tsa_url: Pref<String>,
    pub tsa_policy: Pref<String>,
    pub pdf_timestamp: Pref<PdfTimestamp>,
    pub triphase: Pref<bool>,
    pub server_url: Pref<String>,
}

impl Preferences {
    pub fn load() -> Self {
        Self {
            digest: Pref::new("digest", DigestAlgorithm::Sha512),
            policy: Pref::new("policy", None),
            cades_mode: Pref::new("cadesMode", SignatureMode::Explicit),
            xades_format: Pref::new("xadesFormat", XadesFormat::Enveloping),
            location: Pref::new("location", String::new()),
            visible: Pref::new("visible", false),
            visible_text: Pref::new("visibleText", String::new()),
            font_family: Pref::new("fontFamily", FontFamily::Courier),
            font_size: Pref::new("fontSize", 12.0),
            timestamp: Pref::new("timestamp", false),
            tsa_url: Pref::new("tsaUrl", String::new()),
            tsa_policy: Pref::new("tsaPolicy", String::new()),
            pdf_timestamp: Pref::new("pdfTimestamp", PdfTimestamp::Signature),
            triphase: Pref::new("triphase", false),
            server_url: Pref::new("serverUrl", String::new()),
        }
    }

    /// Back to AutoFirma's defaults. The TSA and server addresses are kept: they
    /// are not choices but facts the user had to look up.
    pub fn reset(&self) {
        self.digest.reset();
        self.policy.reset();
        self.cades_mode.reset();
        self.xades_format.reset();
        self.location.reset();
        self.visible.reset();
        self.visible_text.reset();
        self.font_family.reset();
        self.font_size.reset();
        self.timestamp.reset();
        self.tsa_policy.reset();
        self.pdf_timestamp.reset();
        self.triphase.reset();
    }
}

/// `localStorage`, unless the browser blocks it (private mode, settings).
fn storage() -> Option<Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

fn load<T: DeserializeOwned>(key: &str) -> Option<T> {
    let text = storage()?.get_item(&format!("{PREFIX}{key}")).ok()??;
    let value = js_sys::JSON::parse(&text).ok()?;
    serde_wasm_bindgen::from_value(value).ok()
}

/// Saves `value`, or forgets the key when it is `None` (the default).
fn save<T: Serialize>(key: &str, value: Option<&T>) {
    let Some(storage) = storage() else {
        return;
    };
    let key = format!("{PREFIX}{key}");
    let text = value
        .and_then(|value| serde_wasm_bindgen::to_value(value).ok())
        .and_then(|value| js_sys::JSON::stringify(&value).ok())
        .map(String::from);
    let _ = match text {
        Some(text) => storage.set_item(&key, &text),
        None => storage.remove_item(&key),
    };
}
